//go:build linux && integration

package sensor

import (
	"context"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

// A wakeup recorded before a thread blocks must not turn its sleep into
// runnable latency when it eventually switches back in.
func TestSchedulerDiscardsWakeupBeforeBlock(t *testing.T) {
	cfg := config.Default()
	cfg.Enabled = []string{"scheduler"}
	cfg.Strict = true
	cfg.SchedulerThreshold = time.Second
	cfg.SchedulerCritical = 2 * time.Second
	cfg.DetailRate = 4096
	ss, _, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := ss[0].(*kernelSensor)
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var events []model.Event
	if err := s.Start(ctx, func(e model.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}); err != nil {
		t.Fatal(err)
	}

	runtime.LockOSThread()
	pid := uint32(syscall.Gettid())
	for i := 0; i < 5; i++ {
		// Simulate a wakeup that left a timestamp while this thread was running.
		if err := s.collection.Maps["runnable"].Update(pid, uint64(1), ebpf.UpdateAny); err != nil {
			runtime.UnlockOSThread()
			t.Fatal(err)
		}
		time.Sleep(40 * time.Millisecond)
	}
	runtime.UnlockOSThread()
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	for _, e := range events {
		if e.PID == pid && e.LatencyNS >= uint64(time.Second) {
			t.Fatalf("blocked thread's sleep was reported as runnable latency: %+v", e)
		}
	}
}
