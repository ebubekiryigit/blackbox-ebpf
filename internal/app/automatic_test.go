package app

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/autocapture"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/capture"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/recorder"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/sensor"
)

type automaticSensor struct {
	critical  atomic.Uint64
	snapshots atomic.Uint64
}

func (*automaticSensor) Name() string                             { return "scheduler" }
func (*automaticSensor) Start(context.Context, sensor.Sink) error { return nil }
func (*automaticSensor) Close() error                             { return nil }
func (*automaticSensor) Health() model.SensorHealth {
	return model.SensorHealth{Name: "scheduler", State: "healthy"}
}
func (s *automaticSensor) Snapshot(start, end uint64) (model.Metric, error) {
	s.snapshots.Add(1)
	n := s.critical.Swap(0)
	return model.Metric{Family: "scheduler", StartMonoNS: start, EndMonoNS: end, Count: n, Anomalies: n, Critical: n, Loss: model.Counters{Suppressed: n}}, nil
}

func autoEngine(t *testing.T, c config.Config, logOutput ...io.Writer) (*Engine, *automaticSensor, context.Context) {
	t.Helper()
	s := &automaticSensor{}
	epoch := time.Now()
	output := io.Writer(io.Discard)
	if len(logOutput) > 0 {
		output = logOutput[0]
	}
	e := &Engine{Config: c, sensors: []sensor.Sensor{s}, ingress: make(chan model.Event, 8), Queries: make(chan Query, 8), stopped: make(chan struct{}), clock: func() (uint64, error) { return uint64(100*time.Second + time.Since(epoch)), nil }, logger: slog.New(slog.NewTextHandler(output, nil))}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
		e.Close()
		if e.snapshotBusy.Load() {
			t.Error("snapshot lease leaked at shutdown")
		}
	})
	if _, err := e.Ask(ctx, 0); err != nil {
		t.Fatal(err)
	}
	return e, s, ctx
}
func autoConfig(t *testing.T) config.Config {
	t.Helper()
	c := config.Default()
	c.History = 2 * time.Second
	c.Resources.PollInterval = 100 * time.Millisecond
	c.Resources.SegmentInterval = 100 * time.Millisecond
	c.AutoCapture.Before = time.Second
	c.AutoCapture.After = 200 * time.Millisecond
	c.AutoCapture.Directory = filepath.Join(t.TempDir(), "auto")
	return c
}
func waitAuto(t *testing.T, ctx context.Context, e *Engine, predicate func(*model.AutoCaptureHealth) bool) *model.AutoCaptureHealth {
	t.Helper()
	for {
		r, err := e.Ask(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		if predicate(r.Health.AutoCapture) {
			return r.Health.AutoCapture
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}
func TestAutomaticCaptureThroughRecorderStorageAndReadback(t *testing.T) {
	e, s, ctx := autoEngine(t, autoConfig(t))
	s.critical.Store(2)
	h := waitAuto(t, ctx, e, func(h *model.AutoCaptureHealth) bool { return h.Saved == 1 })
	c, err := capture.ReadFile(h.LastPath)
	if err != nil {
		t.Fatal(err)
	}
	a := c.Manifest.AutoIncident
	if c.Manifest.Health.AutoCapture != nil {
		t.Fatal("transient automatic state was persisted in capture")
	}
	if a == nil || a.EndMonoNS-a.DetectedMonoNS != uint64(e.Config.AutoCapture.After) || a.BeforeNS != uint64(time.Second) || len(a.Triggers) != 1 || a.Triggers[0].Count != 2 {
		t.Fatalf("bad incident %+v", a)
	}
	var counted uint64
	for _, segment := range c.Segments {
		for _, m := range segment.Metrics {
			counted += m.Critical
		}
	}
	if counted != 2 {
		t.Fatalf("trigger aggregates lost/doubled: %d", counted)
	}
	if h.Detected != 2 || h.Coalesced != 1 || h.Failures != 0 {
		t.Fatal(h)
	}
	if c.Manifest.RequestedStartMonoNS != a.DetectedMonoNS-a.BeforeNS || c.Manifest.StartMonoNS <= c.Manifest.RequestedStartMonoNS {
		t.Fatal("startup coverage not preserved")
	}
	// The next critical observation starts another file immediately.
	s.critical.Store(3)
	h = waitAuto(t, ctx, e, func(h *model.AutoCaptureHealth) bool { return h.Saved == 2 })
	second, err := capture.ReadFile(h.LastPath)
	if err != nil || second.Manifest.AutoIncident.Triggers[0].Count != 3 {
		t.Fatal("second incident missing", err)
	}
}
func TestManualSnapshotDuringPostWindowAndAutomaticBusyWait(t *testing.T) {
	cfg := autoConfig(t)
	cfg.AutoCapture.After = 400 * time.Millisecond
	e, s, ctx := autoEngine(t, cfg)
	s.critical.Store(1)
	waitAuto(t, ctx, e, func(h *model.AutoCaptureHealth) bool { return h.State == "pending" })
	manual, err := e.Ask(ctx, time.Second)
	if err != nil {
		t.Fatal("pending automatic incident blocked manual snapshot", err)
	}
	t.Cleanup(manual.ReleaseSnapshot)
	if manual.Health.AutoCapture == nil || manual.Health.AutoCapture.State != "pending" || manual.Capture.Manifest.Health.AutoCapture != nil {
		t.Fatal("manual snapshot persisted transient automatic status", manual.Health.AutoCapture, manual.Capture.Manifest.Health.AutoCapture)
	}
	s.critical.Store(1)
	waitAuto(t, ctx, e, func(h *model.AutoCaptureHealth) bool { return h.Coalesced == 1 })
	// Hold the manual writer beyond the fixed end; status and polling still work.
	time.Sleep(450 * time.Millisecond)
	h := waitAuto(t, ctx, e, func(h *model.AutoCaptureHealth) bool { return h.State == "pending" })
	if h.Saved != 0 {
		t.Fatal("automatic writer overlapped manual writer")
	}
	// A critical observation after the first window must survive the busy
	// manual writer as a second automatic incident.
	s.critical.Store(1)
	waitAuto(t, ctx, e, func(h *model.AutoCaptureHealth) bool { return h.Detected == 3 })
	if _, err = e.Ask(ctx, time.Second); err == nil || !strings.Contains(err.Error(), "already being written") {
		t.Fatal("second manual snapshot accepted", err)
	}
	manual.ReleaseSnapshot()
	h = waitAuto(t, ctx, e, func(h *model.AutoCaptureHealth) bool { return h.Saved == 1 })
	firstPath := h.LastPath
	c, err := capture.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	if c.Manifest.AutoIncident.EndMonoNS != c.Manifest.EndMonoNS || c.Manifest.AutoIncident.AfterNS != uint64(cfg.AutoCapture.After) {
		t.Fatal("writer delay moved the window")
	}
	h = waitAuto(t, ctx, e, func(h *model.AutoCaptureHealth) bool { return h.Saved == 2 })
	if h.LastPath == firstPath {
		t.Fatal("second incident was not published separately")
	}
	c, err = capture.ReadFile(h.LastPath)
	if err != nil || c.Manifest.AutoIncident == nil || c.Manifest.AutoIncident.Triggers[0].Count != 1 {
		t.Fatal("second incident lost behind busy writer", err)
	}
}

func TestBusyAutomaticRetryDoesNotPollSensors(t *testing.T) {
	cfg := autoConfig(t)
	cfg.History = 3 * time.Second
	cfg.Resources.PollInterval = 2 * time.Second
	cfg.AutoCapture.After = 100 * time.Millisecond
	e, s, ctx := autoEngine(t, cfg)
	s.critical.Store(1)
	manual, err := e.Ask(ctx, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer manual.ReleaseSnapshot()
	before := s.snapshots.Load()
	time.Sleep(450 * time.Millisecond)
	if extra := s.snapshots.Load() - before; extra > 1 {
		t.Fatalf("automatic writer retries polled sensor %d times before the next 2s interval", extra)
	}
	manual.ReleaseSnapshot()
	waitAuto(t, ctx, e, func(h *model.AutoCaptureHealth) bool { return h.Saved == 1 })
}

func TestBusyManualRequestArmsAutomaticDeadline(t *testing.T) {
	cfg := autoConfig(t)
	cfg.History = 6 * time.Second
	cfg.Resources.PollInterval = 5 * time.Second
	cfg.AutoCapture.After = 100 * time.Millisecond
	e, s, ctx := autoEngine(t, cfg)
	manual, err := e.Ask(ctx, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer manual.ReleaseSnapshot()
	s.critical.Store(1)
	if _, err := e.Ask(ctx, time.Second); err == nil || !strings.Contains(err.Error(), "already being written") {
		t.Fatal("concurrent manual request was not rejected", err)
	}
	manual.ReleaseSnapshot()
	deadline := time.After(2 * time.Second)
	for {
		entries, err := os.ReadDir(cfg.AutoCapture.Directory)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".bbx") {
				return
			}
		}
		select {
		case <-deadline:
			t.Fatal("busy manual request left automatic deadline unarmed until the next poll")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestConcurrentManualSnapshotsAndPendingAutomaticCapture(t *testing.T) {
	e, s, ctx := autoEngine(t, autoConfig(t))
	const clients = 24
	start := make(chan struct{})
	results := make(chan Result, clients)
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, _ := e.Ask(ctx, time.Second)
			results <- r
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var held func()
	var busy int
	for result := range results {
		switch {
		case result.ReleaseSnapshot != nil:
			if held != nil {
				result.ReleaseSnapshot()
				held()
				t.Fatal("two manual writers owned the snapshot lease")
			}
			held = result.ReleaseSnapshot
		case result.Err != nil && strings.Contains(result.Err.Error(), "already being written"):
			busy++
		default:
			t.Fatalf("unexpected concurrent result: %+v", result)
		}
	}
	if held == nil || busy != clients-1 {
		t.Fatalf("lease results: held=%v busy=%d", held != nil, busy)
	}
	defer func() {
		if held != nil {
			held()
		}
	}()
	s.critical.Store(1)
	h := waitAuto(t, ctx, e, func(h *model.AutoCaptureHealth) bool { return h.State == "pending" })
	if h.Saved != 0 {
		t.Fatal("automatic capture overlapped held manual snapshot")
	}
	time.Sleep(e.Config.AutoCapture.After + e.Config.Resources.PollInterval)
	h = waitAuto(t, ctx, e, func(h *model.AutoCaptureHealth) bool { return h.State == "pending" })
	if h.Saved != 0 {
		t.Fatal("automatic writer bypassed manual lease")
	}
	held()
	held = nil
	h = waitAuto(t, ctx, e, func(h *model.AutoCaptureHealth) bool { return h.Saved == 1 })
	if _, err := capture.ReadFile(h.LastPath); err != nil {
		t.Fatal("automatic capture after writer release is unreadable", err)
	}
}
func TestAutomaticPublishFailureDoesNotStopStrictRecording(t *testing.T) {
	cfg := autoConfig(t)
	cfg.Strict = true
	if err := os.WriteFile(cfg.AutoCapture.Directory, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	e, s, ctx := autoEngine(t, cfg, &logs)
	s.critical.Store(1)
	h := waitAuto(t, ctx, e, func(h *model.AutoCaptureHealth) bool { return h.Failures == 1 })
	if h.State != "armed" || h.LastError == "" || e.SnapshotFailures.Load() != 1 {
		t.Fatal("failure opaque", h)
	}
	if !strings.Contains(logs.String(), "automatic capture failed") {
		t.Fatal("automatic publish failure was not logged", logs.String())
	}
	if err := os.Remove(cfg.AutoCapture.Directory); err != nil {
		t.Fatal(err)
	}
	time.Sleep(cfg.Resources.PollInterval * 3)
	r, err := e.Ask(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Health.AutoCapture.Saved != 0 || r.Health.AutoCapture.Failures != 1 {
		t.Fatal("failed incident retried without a new trigger", r.Health.AutoCapture)
	}
	s.critical.Store(1)
	h = waitAuto(t, ctx, e, func(h *model.AutoCaptureHealth) bool { return h.Saved == 1 })
	if h.LastError != "" {
		t.Fatal("subsequent capture did not clear last error")
	}
	r, err = e.Ask(ctx, time.Second)
	if err != nil {
		t.Fatal("recording stopped on output error", err)
	}
	r.ReleaseSnapshot()
}
func TestAutomaticDisabledDoesNotCreateStorage(t *testing.T) {
	cfg := autoConfig(t)
	cfg.AutoCapture.Enabled = false
	e, s, ctx := autoEngine(t, cfg)
	s.critical.Store(5)
	r, err := e.Ask(ctx, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r.ReleaseSnapshot()
	if r.Health.AutoCapture != nil {
		t.Fatal("disabled auto capture exposed active status")
	}
	if _, err := os.Stat(cfg.AutoCapture.Directory); !os.IsNotExist(err) {
		t.Fatal("disabled auto capture created files")
	}
}
func TestSnapshotLeaseCancellationAndRelease(t *testing.T) {
	e := &Engine{}
	release, ok := e.beginSnapshot()
	if !ok {
		t.Fatal("first lease failed")
	}
	if _, ok = e.beginSnapshot(); ok {
		t.Fatal("second lease accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reply(Query{ctx: ctx, Reply: make(chan Result)}, Result{ReleaseSnapshot: release})
	if e.snapshotBusy.Load() {
		t.Fatal("cancelled reply retained capture lease")
	}
	release() // Idempotent even if an error path also releases.
	release, ok = e.beginSnapshot()
	if !ok {
		t.Fatal("lease not reusable")
	}
	release()
}

func TestAutomaticSelectionHoldsManualSnapshotLease(t *testing.T) {
	cfg := autoConfig(t)
	e := &Engine{Config: cfg}
	a := &automatic{controller: autocapture.New(cfg, model.Families), engine: e, timer: time.NewTimer(time.Hour), jobs: make(chan autoJob, 1)}
	defer a.timer.Stop()
	r := recorder.New(cfg.History, cfg.MaxMemory, uint64(time.Second))
	a.controller.Observe(model.Metric{Family: "oom", StartMonoNS: uint64(time.Second), EndMonoNS: uint64(2 * time.Second), Count: 1}, uint64(2*time.Second))
	end, ok := a.controller.Deadline()
	if !ok {
		t.Fatal("incident was not scheduled")
	}
	a.progress(end, end, r, func() model.Health { return model.Health{} })
	if len(a.jobs) != 1 || !e.snapshotBusy.Load() {
		t.Fatal("automatic selection did not reserve snapshot writer")
	}
	if release, ok := e.beginSnapshot(); ok {
		release()
		t.Fatal("manual writer overlapped automatic selection")
	}
	(<-a.jobs).release()
	if e.snapshotBusy.Load() {
		t.Fatal("automatic writer leaked snapshot lease")
	}
}
func TestAutomaticWaitsForWriterAndPendingShutdown(t *testing.T) {
	cfg := autoConfig(t)
	cfg.Control.Timeout = time.Second
	e := &Engine{Config: cfg}
	a := newAutomatic(context.Background(), e, model.Families)
	r := recorder.New(cfg.History, cfg.MaxMemory, uint64(time.Second))
	a.controller.Observe(model.Metric{Family: "oom", StartMonoNS: uint64(time.Second), EndMonoNS: uint64(2 * time.Second), Count: 1}, uint64(2*time.Second))
	end, _ := a.controller.Deadline()
	release, _ := e.beginSnapshot()
	a.progress(end, end, r, func() model.Health { return model.Health{} })
	if a.controller.Health().State != "pending" {
		t.Fatal("busy writer discarded pending metadata")
	}
	a.progress(end+uint64(time.Second), end+uint64(time.Second), r, func() model.Health { return model.Health{} })
	if a.controller.Health().Failures != 0 || a.controller.Health().State != "pending" {
		t.Fatal("writer contention discarded incident")
	}
	release()
	a.progress(end+uint64(time.Second), end+uint64(time.Second), r, func() model.Health { return model.Health{} })
	select {
	case result := <-a.completed():
		a.finish(result)
		if a.controller.Health().Saved != 1 {
			t.Fatal("waiting incident was not published", result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("writer release did not complete automatic capture")
	}
	a.close()
	b := newAutomatic(context.Background(), e, model.Families)
	b.controller.Observe(model.Metric{Family: "oom", StartMonoNS: 1, EndMonoNS: 2, Count: 1}, 2)
	b.close()
	if e.snapshotBusy.Load() {
		t.Fatal("shutdown leaked writer")
	}
}
