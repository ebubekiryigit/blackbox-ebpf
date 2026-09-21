//go:build linux && integration

package sensor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

// Exercise the real completion lifecycle, including zero-byte hardware FLUSH.
// Fault injection fills only this sensor's private map; it does not alter disk
// configuration, other BPF programs, or the running user's recorder.
func TestBlockFlushSequencingAndRealTrackingLoss(t *testing.T) {
	cfg := config.Default()
	cfg.Enabled = []string{"block_io"}
	cfg.Strict = true
	cfg.BlockThreshold = time.Microsecond
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
	if err = s.Start(ctx, func(e model.Event) { mu.Lock(); events = append(events, e); mu.Unlock() }); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if _, err = s.Snapshot(0, 0); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "fsync-workload"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	workload := func(n int) {
		data := make([]byte, 64<<10)
		for i := 0; i < n; i++ {
			if _, er := f.Write(data); er != nil {
				t.Fatal(er)
			}
			if er := f.Sync(); er != nil {
				t.Fatal(er)
			}
		}
	}
	workload(32)
	time.Sleep(150 * time.Millisecond)
	m, err := s.Snapshot(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if m.Count == 0 || m.Count != m.Histogram.Count() {
		t.Fatalf("missing matched latency observations: %+v", m)
	}
	if m.Loss.Unmatched != 0 || m.Loss.TrackingFailures != 0 {
		t.Fatalf("ordinary fsync produced false measurement loss: %+v", m)
	}
	mu.Lock()
	flushes := 0
	for _, e := range events {
		if e.Operation == "flush" && e.Bytes == 0 && e.LatencyNS > 0 {
			flushes++
		}
	}
	mu.Unlock()
	if m.BookkeepingCompletions > 0 && flushes == 0 {
		t.Fatal("flush bookkeeping was seen but physical zero-byte flush latency was discarded")
	}
	t.Logf("32 fsyncs: matched=%d bookkeeping=%d unmatched=%d retained physical flushes=%d", m.Count, m.BookkeepingCompletions, m.Loss.Unmatched, flushes)

	// Force genuine missing tracking records on subsequent dispatched I/O.
	starts := s.collection.Maps["starts"]
	saved := 0
	for k := uint64(1); k <= uint64(starts.MaxEntries()); k++ {
		if er := starts.Update(k, blockInflight{}, ebpf.UpdateAny); er != nil {
			if errors.Is(er, syscall.E2BIG) || errors.Is(er, syscall.ENOSPC) {
				break
			}
			t.Fatal(er)
		}
		saved++
	}
	if saved < 8000 {
		t.Fatalf("private tracking map was unexpectedly occupied: %d entries inserted", saved)
	}
	workload(8)
	time.Sleep(150 * time.Millisecond)
	m, err = s.Snapshot(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if m.Loss.TrackingFailures == 0 || m.Loss.Unmatched == 0 {
		t.Fatalf("real tracking loss was hidden by bookkeeping filter: %+v", m)
	}
	t.Logf("private map exhausted: tracking failures=%d unmatched=%d bookkeeping=%d", m.Loss.TrackingFailures, m.Loss.Unmatched, m.BookkeepingCompletions)
}
