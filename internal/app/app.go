package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/logging"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/process"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/recorder"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/sensor"
)

type Query struct {
	Last  time.Duration
	Reply chan Result
}
type Result struct {
	Health  model.Health
	Capture model.Capture
	Err     error
}
type Engine struct {
	Config           config.Config
	logger           *slog.Logger
	sensors          []sensor.Sensor
	unavailable      []model.SensorHealth
	host             model.Host
	ingress          chan model.Event
	Queries          chan Query
	ingressDrops     atomic.Uint64
	SnapshotFailures atomic.Uint64
	closeMu          sync.Mutex
	closedSensors    map[string]bool
	clock            func() (uint64, error)
	stopped          chan struct{}
}

func New(c config.Config) (*Engine, error) {
	return NewWithLogger(c, logging.New(c.LogLevel, os.Stderr))
}

func NewWithLogger(c config.Config, logger *slog.Logger) (*Engine, error) {
	if logger == nil {
		logger = logging.New(c.LogLevel, os.Stderr)
	}
	if e := c.Validate(); e != nil {
		return nil, e
	}
	h, e := hostInfo()
	if e != nil {
		return nil, e
	}
	ss, missing, e := sensor.Open(c)
	if e != nil {
		return nil, e
	}
	for _, s := range missing {
		logger.Warn("sensor coverage", "sensor", s.Name, "state", s.State, "reason", s.Reason)
	}
	return &Engine{Config: c, logger: logger, sensors: ss, unavailable: missing, host: h, ingress: make(chan model.Event, c.Resources.IngressEvents), Queries: make(chan Query, c.Resources.QueryQueue), clock: Mono, stopped: make(chan struct{})}, nil
}
func (e *Engine) Close() {
	for _, s := range e.sensors {
		e.closeSensor(s)
	}
}

func (e *Engine) RecordSnapshotFailure(err error) {
	total := e.SnapshotFailures.Add(1)
	if e.logger != nil {
		e.logger.Error("snapshot stream failed", "error", err, "total", total)
	}
}

func (e *Engine) closeSensor(s sensor.Sensor) {
	e.closeMu.Lock()
	if e.closedSensors == nil {
		e.closedSensors = make(map[string]bool)
	}
	if e.closedSensors[s.Name()] {
		e.closeMu.Unlock()
		return
	}
	e.closedSensors[s.Name()] = true
	e.closeMu.Unlock()
	if err := s.Close(); err != nil && e.logger != nil {
		e.logger.Error("sensor close failed", "sensor", s.Name(), "error", err)
	}
}
func (e *Engine) Ask(ctx context.Context, last time.Duration) (Result, error) {
	q := Query{Last: last, Reply: make(chan Result, 1)}
	select {
	case e.Queries <- q:
	case <-ctx.Done():
		return Result{}, ctx.Err()
	case <-e.stopped:
		return Result{}, fmt.Errorf("recorder stopped")
	}
	select {
	case r := <-q.Reply:
		return r, r.Err
	case <-ctx.Done():
		return Result{}, ctx.Err()
	case <-e.stopped:
		return Result{}, fmt.Errorf("recorder stopped")
	}
}
func (e *Engine) Run(ctx context.Context) error {
	logger := e.logger
	if logger == nil {
		logger = logging.New(e.Config.LogLevel, os.Stderr)
	}
	if e.stopped != nil {
		defer close(e.stopped)
	}
	clock := e.clock
	if clock == nil {
		clock = Mono
	}
	now, err := clock()
	if err != nil {
		return err
	}
	metadata := process.NewWithPathLimit("/proc", e.Config.Resources.MetadataEntries, e.Config.Resources.MetadataPathBytes)
	r := recorder.NewWithSegmentInterval(e.Config.History, e.Config.MaxMemory, e.Config.Resources.SegmentInterval, now)
	var ingressOverloadLogged atomic.Bool
	recorderOverloadLogged := false
	sink := func(v model.Event) {
		select {
		case e.ingress <- v:
		default:
			total := e.ingressDrops.Add(1)
			if ingressOverloadLogged.CompareAndSwap(false, true) {
				logger.Warn("event ingress overloaded; details are being dropped", "total", total, "counter", "ingress_drops")
			}
		}
	}
	var ready []sensor.Sensor
	for _, s := range e.sensors {
		_, err = s.Snapshot(now, now) // Exclude attachment/startup activity from interval counts.
		if err == nil {
			err = s.Start(ctx, sink)
		}
		if err != nil {
			e.closeSensor(s)
			if e.Config.Strict {
				return fmt.Errorf("strict mode: %s failed initialization: %w", s.Name(), err)
			}
			e.unavailable = append(e.unavailable, model.SensorHealth{Name: s.Name(), State: "unavailable", Reason: err.Error()})
			logger.Error("sensor initialization failed", "sensor", s.Name(), "error", err)
			continue
		}
		ready = append(ready, s)
	}
	e.sensors = ready
	if len(ready) == 0 {
		return fmt.Errorf("no sensor initialized successfully")
	}
	timer := time.NewTicker(e.Config.Resources.PollInterval)
	defer timer.Stop()
	previous := now
	disabled := map[string]bool{}
	health := func() model.Health {
		h := r.Health()
		h.MetadataFailures = metadata.Failures
		h.IngressDrops = e.ingressDrops.Load()
		h.SnapshotFailures = e.SnapshotFailures.Load()
		h.Sensors = append(h.Sensors, e.unavailable...)
		for _, s := range e.sensors {
			h.Sensors = append(h.Sensors, s.Health())
		}
		sort.Slice(h.Sensors, func(i, j int) bool { return h.Sensors[i].Name < h.Sensors[j].Name })
		return h
	}
	collect := func(end uint64) error {
		for _, s := range e.sensors {
			if disabled[s.Name()] {
				continue
			}
			if h := s.Health(); h.State != "healthy" {
				disabled[s.Name()] = true
				e.closeSensor(s)
				if e.Config.Strict {
					return fmt.Errorf("strict mode: %s failed permanently: %s", h.Name, h.Reason)
				}
				logger.Error("sensor failed permanently", "sensor", h.Name, "reason", h.Reason)
				continue
			}
			m, er := s.Snapshot(previous, end)
			if er != nil {
				disabled[s.Name()] = true
				e.closeSensor(s)
				if e.Config.Strict {
					return fmt.Errorf("strict mode: %s failed permanently: %w", s.Name(), er)
				}
				logger.Error("sensor aggregation failed", "sensor", s.Name(), "error", er)
				continue
			}
			if !r.Metric(m, end) && !recorderOverloadLogged {
				recorderOverloadLogged = true
				logger.Warn("recorder memory budget exhausted; observations are being dropped", "counter", "recorder_drops")
			}
		}
		previous = end
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case v := <-e.ingress:
			now, err = clock()
			if err != nil {
				return err
			}
			if !r.Event(metadata.Enrich(v), now) && !recorderOverloadLogged {
				recorderOverloadLogged = true
				logger.Warn("recorder memory budget exhausted; observations are being dropped", "counter", "recorder_drops")
			}
		case <-timer.C:
			now, err = clock()
			if err != nil {
				return err
			}
			r.Advance(now)
			if err = collect(now); err != nil {
				return err
			}
		case q := <-e.Queries:
			now, err = clock()
			if err != nil {
				return err
			}
			r.Advance(now)
			if q.Last < 0 || q.Last > e.Config.History {
				q.Reply <- Result{Err: fmt.Errorf("snapshot window must be positive and at most configured history %s", e.Config.History)}
				continue
			}
			// Drain only the queue contents already present, so requests cannot starve recording.
			n := len(e.ingress)
			for i := 0; i < n; i++ {
				v := <-e.ingress
				now, err = clock()
				if err != nil {
					q.Reply <- Result{Err: err}
					return err
				}
				if !r.Event(metadata.Enrich(v), now) && !recorderOverloadLogged {
					recorderOverloadLogged = true
					logger.Warn("recorder memory budget exhausted; observations are being dropped", "counter", "recorder_drops")
				}
			}
			now, err = clock()
			if err != nil {
				q.Reply <- Result{Err: err}
				return err
			}
			if q.Last > 0 {
				if err = collect(now); err != nil {
					q.Reply <- Result{Err: err}
					return err
				}
			}
			h := health()
			result := Result{Health: h}
			if q.Last > 0 {
				result.Capture = r.Snapshot(q.Last, now, e.host, h, "ebpf")
				result.Capture.Manifest.Settings = e.Settings()
			}
			q.Reply <- result
		}
	}
}

// Settings is the durable subset needed to interpret this recording. Client
// transport limits and presentation choices are not workload evidence.
func (e *Engine) Settings() model.RecordingSettings {
	return model.RecordingSettings{HistoryNS: uint64(e.Config.History), MaxMemory: e.Config.MaxMemory, BlockThresholdNS: uint64(e.Config.BlockThreshold), SchedulerThresholdNS: uint64(e.Config.SchedulerThreshold), BlockCriticalNS: uint64(e.Config.BlockCritical), SchedulerCriticalNS: uint64(e.Config.SchedulerCritical), DetailRate: e.Config.DetailRate, Enabled: append([]string(nil), e.Config.Enabled...), Strict: e.Config.Strict, PollIntervalNS: uint64(e.Config.Resources.PollInterval), SegmentIntervalNS: uint64(e.Config.Resources.SegmentInterval), IngressEvents: e.Config.Resources.IngressEvents, MetadataEntries: e.Config.Resources.MetadataEntries, BlockTrackingEntries: e.Config.Resources.BlockTrackingEntries, SchedulerTrackingEntries: e.Config.Resources.SchedulerTrackingEntries, RingBytes: e.Config.Resources.RingBytes}
}
