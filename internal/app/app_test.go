package app

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/sensor"
)

type failingSensor struct {
	mu     sync.Mutex
	name   string
	failed bool
	closes int
}

func (s *failingSensor) Name() string {
	if s.name == "" {
		return "block_io"
	}
	return s.name
}
func (*failingSensor) Start(context.Context, sensor.Sink) error { return nil }
func (s *failingSensor) Snapshot(start, end uint64) (model.Metric, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return model.Metric{}, fmt.Errorf("permanent map read failure")
	}
	return model.Metric{Family: s.Name(), StartMonoNS: start, EndMonoNS: end}, nil
}
func (s *failingSensor) Health() model.SensorHealth {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := "healthy"
	if s.failed {
		state = "error"
	}
	return model.SensorHealth{Name: s.Name(), State: state, Reason: "permanent map read failure"}
}
func (s *failingSensor) Close() error { s.mu.Lock(); defer s.mu.Unlock(); s.closes++; return nil }
func TestPermanentFailureStrictAndBestEffort(t *testing.T) {
	for _, tc := range []struct {
		name    string
		strict  bool
		sensors int
	}{
		{"best-effort last sensor", false, 1},
		{"best-effort partial then last", false, 2},
		{"strict partial failure", true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := config.Default()
			c.Strict = tc.strict
			first := &failingSensor{name: "block_io"}
			sensors := []sensor.Sensor{first}
			var second *failingSensor
			if tc.sensors == 2 {
				second = &failingSensor{name: "scheduler"}
				sensors = append(sensors, second)
			}
			epoch := time.Now()
			e := &Engine{Config: c, sensors: sensors, ingress: make(chan model.Event, 2), Queries: make(chan Query, 2), clock: func() (uint64, error) { return uint64(time.Second + time.Since(epoch)), nil }, stopped: make(chan struct{})}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- e.Run(ctx) }()
			if _, err := e.Ask(ctx, 0); err != nil {
				t.Fatal(err)
			}
			first.mu.Lock()
			first.failed = true
			first.mu.Unlock()
			result, err := e.Ask(ctx, time.Second)
			if !tc.strict && tc.sensors == 2 {
				if err != nil {
					t.Fatal(err)
				}
				if result.Capture.Manifest.Health.Sensors[0].State != "error" || result.Capture.Manifest.Health.Sensors[1].State != "healthy" {
					t.Fatal("missing coverage not captured")
				}
				result.ReleaseSnapshot()
				if _, err = e.Ask(ctx, 0); err != nil {
					t.Fatal("best-effort stopped with a working sensor", err)
				}
				second.mu.Lock()
				second.failed = true
				second.mu.Unlock()
				_, err = e.Ask(ctx, time.Second)
			}
			if err == nil || (tc.strict && !strings.Contains(err.Error(), "failed permanently")) || (!tc.strict && !strings.Contains(err.Error(), "no active sensors")) {
				t.Fatalf("daemon accepted permanent loss of required coverage: %v", err)
			}
			if runErr := <-done; runErr == nil {
				t.Fatal("daemon exited successfully after permanent sensor failure")
			}
			e.Close()
			for _, s := range []*failingSensor{first, second} {
				if s == nil {
					continue
				}
				s.mu.Lock()
				closes := s.closes
				s.mu.Unlock()
				if closes != 1 {
					t.Fatalf("%s closed %d times", s.Name(), closes)
				}
			}
		})
	}
}

type burstSensor struct{}

func (*burstSensor) Name() string { return "block_io" }
func (*burstSensor) Snapshot(start, end uint64) (model.Metric, error) {
	return model.Metric{Family: "block_io", StartMonoNS: start, EndMonoNS: end}, nil
}
func (*burstSensor) Health() model.SensorHealth {
	return model.SensorHealth{Name: "block_io", State: "healthy"}
}
func (*burstSensor) Close() error { return nil }
func (*burstSensor) Start(_ context.Context, sink sensor.Sink) error {
	for i := 0; i < 100; i++ {
		sink(model.Event{Type: "block_io", MonoNS: uint64(time.Second)})
	}
	return nil
}

func TestIngressOverloadLogsOnceAndRemainsVisible(t *testing.T) {
	c := config.Default()
	c.Resources.IngressEvents = 1
	var logs bytes.Buffer
	e := &Engine{Config: c, logger: slog.New(slog.NewTextHandler(&logs, nil)), sensors: []sensor.Sensor{&burstSensor{}}, ingress: make(chan model.Event, 1), Queries: make(chan Query, 1), clock: func() (uint64, error) { return uint64(time.Second), nil }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for e.ingressDrops.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if e.ingressDrops.Load() == 0 || strings.Count(logs.String(), "event ingress overloaded") != 1 {
		t.Fatalf("overload not visible or noisy: drops=%d logs=%q", e.ingressDrops.Load(), logs.String())
	}
}

func TestRecorderOverloadLogsOnceAndRemainsVisible(t *testing.T) {
	c := config.Default()
	// A segment alone consumes this budget, so every observation is rejected.
	c.MaxMemory = 512
	c.Resources.IngressEvents = 128
	var logs bytes.Buffer
	e := &Engine{Config: c, logger: slog.New(slog.NewTextHandler(&logs, nil)), sensors: []sensor.Sensor{&burstSensor{}}, ingress: make(chan model.Event, c.Resources.IngressEvents), Queries: make(chan Query, 1), clock: func() (uint64, error) { return uint64(time.Second), nil }}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	var drops uint64
	for drops == 0 && ctx.Err() == nil {
		result, err := e.Ask(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		drops = result.Health.RecorderDrops
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if drops == 0 || strings.Count(logs.String(), "recorder memory budget exhausted") != 1 {
		t.Fatalf("recorder overload not visible or noisy: drops=%d logs=%q", drops, logs.String())
	}
}

func TestSnapshotFailureIsCountedAndLogged(t *testing.T) {
	var logs bytes.Buffer
	e := &Engine{logger: slog.New(slog.NewTextHandler(&logs, nil))}
	e.RecordSnapshotFailure(fmt.Errorf("client disconnected"))
	if e.SnapshotFailures.Load() != 1 || !strings.Contains(logs.String(), "snapshot stream failed") || !strings.Contains(logs.String(), "client disconnected") {
		t.Fatalf("snapshot failure remained opaque: count=%d logs=%q", e.SnapshotFailures.Load(), logs.String())
	}
}
