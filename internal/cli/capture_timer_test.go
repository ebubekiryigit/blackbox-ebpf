package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCaptureDurationStartsAfterReadiness(t *testing.T) {
	const duration = 20 * time.Millisecond
	ready := make(chan struct{})
	run := make(chan error, 1)
	started := make(chan struct{})
	done := make(chan struct {
		finished bool
		err      error
	}, 1)
	go func() {
		close(started)
		finished, err := waitCapturePeriod(context.Background(), ready, run, duration)
		done <- struct {
			finished bool
			err      error
		}{finished, err}
	}()
	<-started
	select {
	case result := <-done:
		t.Fatalf("capture duration elapsed before readiness: %+v", result)
	case <-time.After(3 * duration):
	}
	readyAt := time.Now()
	close(ready)
	select {
	case result := <-done:
		if result.finished || result.err != nil || time.Since(readyAt) < duration {
			t.Fatalf("capture completed before the requested post-readiness duration: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("capture duration did not finish")
	}
}

func TestCaptureWaitPropagatesStartupFailureAndCancellation(t *testing.T) {
	for _, test := range []struct {
		name         string
		ready        bool
		runErr       error
		cancel       bool
		wantFinished bool
		wantError    string
	}{
		{"startup failure", false, errors.New("sensor startup failed"), false, true, "sensor startup failed"},
		{"unexpected recorder stop", false, nil, false, true, "recorder stopped before capture completed"},
		{"cancel before readiness", false, nil, true, false, "context canceled"},
		{"cancel after readiness", true, nil, true, false, "context canceled"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready := make(chan struct{})
			if test.ready {
				close(ready)
			}
			run := make(chan error, 1)
			if test.wantFinished {
				run <- test.runErr
			}
			if test.cancel {
				cancel()
			}
			finished, err := waitCapturePeriod(ctx, ready, run, time.Second)
			if finished != test.wantFinished || err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("finished=%t error=%v", finished, err)
			}
		})
	}
}
