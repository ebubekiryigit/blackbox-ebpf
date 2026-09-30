//go:build linux && integration

package sensor

import (
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
)

func TestSharedDetailBudgetSuppressesWithoutLosingAggregates(t *testing.T) {
	cfg := config.Default()
	cfg.Enabled = []string{"scheduler"}
	cfg.Strict = true
	cfg.SchedulerThreshold = time.Nanosecond
	cfg.SchedulerCritical = 2 * time.Nanosecond
	cfg.DetailRate = 4
	ss, _, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := ss[0].(*kernelSensor)
	defer s.Close()
	if _, err := s.Snapshot(0, 0); err != nil {
		t.Fatal(err)
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		t.Fatal(err)
	}
	// Pre-exhaust two adjacent seconds so the test remains valid at a boundary.
	budget := s.collection.Maps["detail_budgets"]
	for _, sec := range []uint64{uint64(now.Sec), uint64(now.Sec + 1)} {
		if err := budget.Update(sec, uint64(cfg.DetailRate), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	runtime.LockOSThread()
	for i := 0; i < 40; i++ {
		time.Sleep(time.Millisecond)
	}
	runtime.UnlockOSThread()
	m, err := s.Snapshot(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if m.Count == 0 || m.Anomalies == 0 || m.Loss.Suppressed == 0 {
		t.Fatalf("shared quota hid aggregate activity or did not suppress details: %+v", m)
	}
}
