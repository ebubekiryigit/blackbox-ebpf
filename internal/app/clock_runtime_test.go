package app

import (
	"context"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/sensor"
)

func TestRunContinuesAcrossWallClockDiscontinuity(t *testing.T) {
	base := time.Date(2026, 9, 27, 15, 0, 0, 0, time.UTC)
	samples := []clockSample{
		{uint64(100 * time.Second), base},
		{uint64(101 * time.Second), base.Add(14*time.Hour + time.Second)},
		{uint64(102 * time.Second), base.Add(14*time.Hour + 2*time.Second)},
	}
	index := 0 // Only the recording loop calls these functions.
	c := config.Default()
	c.AutoCapture.Enabled = false
	e := &Engine{
		Config: c, sensors: []sensor.Sensor{&failingSensor{name: "scheduler"}},
		host:    model.Host{ClockSource: "boottime", AnchorMonoNS: samples[0].bootNS, AnchorWall: base},
		ingress: make(chan model.Event, 2), Queries: make(chan Query, 2), stopped: make(chan struct{}),
		sampleClock: func() (clockSample, error) {
			sample := samples[min(index, len(samples)-1)]
			index++
			return sample, nil
		},
		clock: func() (uint64, error) { return samples[min(max(index-1, 0), len(samples)-1)].bootNS, nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- e.RunWithReady(ctx, ready) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("recorder stopped before readiness: %v", err)
	case <-ctx.Done():
		t.Fatal("recorder did not become ready")
	}
	result, err := e.Ask(ctx, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got := result.Capture
	result.ReleaseSnapshot()
	if got.Manifest.Health.ClockChanges != 1 || got.Manifest.Health.LastClockChange == nil || got.Host.AnchorMonoNS != samples[1].bootNS || !got.Host.AnchorWall.Equal(samples[1].wall) {
		t.Fatalf("capture did not use the current clock sample: %+v", got)
	}
	status, err := e.Ask(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if status.Health.ClockChanges != 1 || status.Health.ObservedAt == nil || !status.Health.ObservedAt.Equal(samples[2].wall) || status.Health.LastClockChange == nil {
		t.Fatalf("running recorder did not expose current realtime and clock health: %+v", status.Health)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("recorder stopped with an error after a wall-clock step: %v", err)
	}
	e.Close()
}
