//go:build linux && integration

package sensor

import (
	"errors"
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
	if now.Sec < 4 {
		t.Skip("kernel uptime is too short to test expired budget removal")
	}
	old := uint64(now.Sec - 3)
	if err := budget.Update(old, uint64(1), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Snapshot(1, uint64(now.Sec)*uint64(time.Second)); err != nil {
		t.Fatal(err)
	}
	var used uint64
	if err := budget.Lookup(old, &used); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("expired budget survived aggregate poll: %v", err)
	}
	if err := budget.Lookup(uint64(now.Sec), &used); err != nil {
		t.Fatalf("active budget was removed: %v", err)
	}
	if used < uint64(cfg.DetailRate) {
		t.Fatalf("active budget was reset during cleanup: used=%d", used)
	}
}

func TestDetailBudgetSurvivesDelayedAggregatePoll(t *testing.T) {
	cfg := config.Default()
	cfg.Resources.PollInterval = time.Minute
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
	if now.Sec < 70 {
		t.Skip("kernel uptime is too short to simulate a delayed poll")
	}
	// Keep 70 completed seconds in the real BPF map without userspace cleanup.
	// A scheduler event in the active second must still have quota state.
	budget := s.collection.Maps["detail_budgets"]
	for sec := uint64(now.Sec - 70); sec < uint64(now.Sec); sec++ {
		if err := budget.Update(sec, uint64(0), ebpf.UpdateAny); err != nil {
			t.Fatalf("reserve quota state for second %d: %v", sec, err)
		}
	}
	runtime.LockOSThread()
	for i := 0; i < 40; i++ {
		time.Sleep(time.Millisecond)
	}
	runtime.UnlockOSThread()
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		t.Fatal(err)
	}
	m, err := s.Snapshot(0, uint64(now.Sec)*uint64(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if m.Count == 0 || m.Anomalies == 0 || m.Loss.DetailFailures != 0 {
		t.Fatalf("delayed poll lost aggregate activity or event detail quota: %+v", m)
	}
}
