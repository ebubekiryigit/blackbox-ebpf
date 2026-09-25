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
	failed bool
	closes int
}

func (*failingSensor) Name() string                             { return "block_io" }
func (*failingSensor) Start(context.Context, sensor.Sink) error { return nil }
func (s *failingSensor) Snapshot(start, end uint64) (model.Metric, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return model.Metric{}, fmt.Errorf("permanent map read failure")
	}
	return model.Metric{Family: "block_io", StartMonoNS: start, EndMonoNS: end}, nil
}
func (s *failingSensor) Health() model.SensorHealth {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := "healthy"
	if s.failed {
		state = "error"
	}
	return model.SensorHealth{Name: "block_io", State: state, Reason: "permanent map read failure"}
}
func (s *failingSensor) Close() error { s.mu.Lock(); defer s.mu.Unlock(); s.closes++; return nil }
func TestPermanentFailureStrictAndBestEffort(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprint(strict), func(t *testing.T) {
			c := config.Default()
			c.Strict = strict
			s := &failingSensor{}
			epoch := time.Now()
			e := &Engine{Config: c, sensors: []sensor.Sensor{s}, ingress: make(chan model.Event, 2), Queries: make(chan Query, 2), clock: func() (uint64, error) { return uint64(time.Second + time.Since(epoch)), nil }}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- e.Run(ctx) }()
			if _, err := e.Ask(ctx, 0); err != nil {
				t.Fatal(err)
			}
			s.mu.Lock()
			s.failed = true
			s.mu.Unlock()
			result, err := e.Ask(ctx, time.Second)
			if strict {
				if err == nil {
					t.Fatal("strict mode tolerated permanent failure")
				}
				if runErr := <-done; runErr == nil {
					t.Fatal("strict mode exited successfully")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer result.ReleaseSnapshot()
				if result.Capture.Manifest.Health.Sensors[0].State != "error" {
					t.Fatal("missing coverage not captured")
				}
				if _, err = e.Ask(ctx, 0); err != nil {
					t.Fatal("best-effort daemon stopped")
				}
				cancel()
				if runErr := <-done; runErr != nil {
					t.Fatal(runErr)
				}
			}
			e.Close()
			s.mu.Lock()
			closes := s.closes
			s.mu.Unlock()
			if closes != 1 {
				t.Fatalf("sensor closed %d times", closes)
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
