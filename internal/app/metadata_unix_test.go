//go:build darwin || linux

package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/sensor"
)

type metadataTestSensor struct {
	name  string
	sinks chan sensor.Sink
}

func (s *metadataTestSensor) Name() string { return s.name }
func (s *metadataTestSensor) Start(_ context.Context, sink sensor.Sink) error {
	s.sinks <- sink
	return nil
}
func (*metadataTestSensor) Close() error { return nil }
func (s *metadataTestSensor) Health() model.SensorHealth {
	return model.SensorHealth{Name: s.name, State: "healthy"}
}
func (s *metadataTestSensor) Snapshot(start, end uint64) (model.Metric, error) {
	return model.Metric{Family: s.name, StartMonoNS: start, EndMonoNS: end}, nil
}

func TestBlockedMetadataReadDoesNotStallRecorder(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "42")
	if err := os.Mkdir(proc, 0700); err != nil {
		t.Fatal(err)
	}
	stat := "42 (worker) S " + strings.Repeat("0 ", 18) + "1000 0\n"
	if err := os.WriteFile(filepath.Join(proc, "stat"), []byte(stat), 0600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(proc, "cgroup")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "43")
	if err := os.Mkdir(other, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "stat"), []byte("43 (other) S "+strings.Repeat("0 ", 18)+"1000 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "cgroup"), []byte("0::/services/other\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.AutoCapture.Enabled = false
	s := &metadataTestSensor{name: "scheduler", sinks: make(chan sensor.Sink, 1)}
	otherSensor := &metadataTestSensor{name: "oom", sinks: make(chan sensor.Sink, 1)}
	started := time.Now()
	e := &Engine{Config: cfg, sensors: []sensor.Sensor{s, otherSensor}, metadataRoot: root, ingress: make(chan model.Event, 8), Queries: make(chan Query, 8), stopped: make(chan struct{}), clock: func() (uint64, error) {
		return uint64(10*time.Second + time.Since(started)), nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- e.RunWithReady(ctx, ready) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("recorder did not start")
	}
	sink := <-s.sinks
	enriched := make(chan struct{})
	go func() {
		sink(model.Event{Type: "scheduler", MonoNS: uint64(10 * time.Second), TGID: 42, ProcessStartNS: uint64(10 * time.Second)})
		close(enriched)
	}()
	// A nonblocking writer opens only once the resolver is blocked opening the
	// FIFO for reading. Keep it open so the metadata read remains blocked.
	var fd int
	deadline := time.Now().Add(time.Second)
	for {
		var err error
		fd, err = unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.ENXIO) || time.Now().After(deadline) {
			t.Fatalf("metadata read did not reach FIFO: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	defer unix.Close(fd)
	select {
	case <-enriched:
		t.Fatal("metadata read unexpectedly completed")
	default:
	}
	otherEnriched := make(chan struct{})
	go func() {
		(<-otherSensor.sinks)(model.Event{Type: "oom", MonoNS: uint64(10 * time.Second), TGID: 43, ProcessStartNS: uint64(10 * time.Second)})
		close(otherEnriched)
	}()
	select {
	case <-otherEnriched:
	case <-time.After(time.Second):
		t.Fatal("blocked metadata read stalled another sensor reader")
	}
	queryCtx, stop := context.WithTimeout(ctx, 200*time.Millisecond)
	defer stop()
	if _, err := e.Ask(queryCtx, 0); err != nil {
		t.Fatalf("blocked process metadata stalled recorder status: %v", err)
	}
	if _, err := unix.Write(fd, []byte("0::/services/worker\n")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	select {
	case <-enriched:
	case <-time.After(time.Second):
		t.Fatal("metadata read did not resume")
	}
}
