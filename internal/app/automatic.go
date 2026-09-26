package app

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/autocapture"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/recorder"
)

type autoJob struct {
	capture model.Capture
	release func()
}
type autoResult struct {
	path string
	at   time.Time
	err  error
}

type automatic struct {
	controller *autocapture.Controller
	engine     *Engine
	timer      *time.Timer
	jobs       chan autoJob
	results    chan autoResult
	cancel     context.CancelFunc
	done       chan struct{}
	retrying   bool
}

func newAutomatic(ctx context.Context, e *Engine, available []string) *automatic {
	if !e.Config.AutoCapture.Enabled {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	a := &automatic{controller: autocapture.New(e.Config, available), engine: e, timer: time.NewTimer(time.Hour), jobs: make(chan autoJob, 1), results: make(chan autoResult, 1), cancel: cancel, done: make(chan struct{})}
	a.timer.Stop()
	go func() {
		defer close(a.done)
		for {
			select {
			case <-ctx.Done():
				return
			case job := <-a.jobs:
				writeCtx, stop := context.WithTimeout(ctx, e.Config.AutoCapture.WriteTimeout)
				path, err := (autocapture.Store{Config: e.Config}).Save(writeCtx, job.capture)
				stop()
				job.capture = model.Capture{}
				job.release()
				a.results <- autoResult{path, time.Now().UTC(), err}
			}
		}
	}()
	return a
}
func (a *automatic) close() {
	if a == nil {
		return
	}
	a.timer.Stop()
	a.cancel()
	<-a.done
	// Cancellation may win the worker select before it receives a queued job.
	select {
	case job := <-a.jobs:
		job.release()
	default:
	}
}
func (a *automatic) tick() <-chan time.Time {
	if a == nil {
		return nil
	}
	return a.timer.C
}
func (a *automatic) retryTick() bool { return a != nil && a.retrying }
func (a *automatic) completed() <-chan autoResult {
	if a == nil {
		return nil
	}
	return a.results
}

func (a *automatic) finish(result autoResult) {
	a.controller.Finish(result.path, result.at, result.err)
	if result.err != nil {
		a.engine.RecordSnapshotFailure(fmt.Errorf("automatic capture failed: %w", result.err))
	} else if a.engine.logger != nil {
		a.engine.logger.Info("automatic capture saved", "path", result.path)
	}
}
func (a *automatic) progress(now, collectedUntil uint64, r *recorder.Recorder, health func() model.Health) {
	if a == nil {
		return
	}
	end, pending := a.controller.Deadline()
	if !pending {
		a.retrying = false
		return
	}
	if now < end {
		a.retrying = false
		a.timer.Reset(time.Duration(end - now))
		return
	}
	if collectedUntil < end {
		a.retrying = false
		a.timer.Reset(0)
		return
	}
	release, ok := a.engine.beginSnapshot()
	if !ok {
		a.retrying = true
		a.timer.Reset(config.AutoRetryInterval)
		return
	}
	a.retrying = false
	incident := a.controller.Begin()
	start := uint64(0)
	if incident.DetectedMonoNS > incident.BeforeNS {
		start = incident.DetectedMonoNS - incident.BeforeNS
	}
	h := health()
	h.AutoCapture = nil // Live scheduling state is not part of the captured evidence.
	c := r.SnapshotWindow(start, incident.EndMonoNS, a.engine.host, h, "ebpf")
	c.Manifest.Settings = a.engine.Settings()
	c.Manifest.AutoIncident = &incident
	a.jobs <- autoJob{c, release}
}

// The lease covers selection and encoding for both manual and automatic captures.
// Cancellation returns ownership to the loop until the reply is delivered.
func (e *Engine) beginSnapshot() (func(), bool) {
	if !e.snapshotBusy.CompareAndSwap(false, true) {
		return nil, false
	}
	var once sync.Once
	return func() { once.Do(func() { e.snapshotBusy.Store(false) }) }, true
}
func reply(q Query, result Result) {
	select {
	case q.Reply <- result:
	case <-q.ctx.Done():
		if result.ReleaseSnapshot != nil {
			result.ReleaseSnapshot()
		}
	}
}
