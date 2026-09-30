package app

import (
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestClockTrackerRefreshesAnchorAndDetectsOffsetChange(t *testing.T) {
	base := time.Date(2026, 9, 27, 15, 0, 0, 0, time.UTC)
	tracker := newClockTracker(model.Host{ClockSource: "boottime", AnchorMonoNS: uint64(100 * time.Second), AnchorWall: base})
	if step, err := tracker.observe(clockSample{uint64(101 * time.Second), base.Add(time.Second)}); err != nil || step != nil {
		t.Fatalf("stable clocks created a discontinuity: %+v, %v", step, err)
	}
	jump := base.Add(14*time.Hour + 2*time.Second)
	step, err := tracker.observe(clockSample{uint64(102 * time.Second), jump})
	if err != nil || step == nil || tracker.changes != 1 || step.OffsetChangeNS != int64(14*time.Hour) {
		t.Fatalf("clock step was not recorded: step=%+v err=%v tracker=%+v", step, err, tracker)
	}
	if step.DetectedBootNS != uint64(102*time.Second) || !step.DetectedAt.Equal(jump) {
		t.Fatalf("incorrect latest discontinuity: %+v", step)
	}
	if tracker.host.AnchorMonoNS != uint64(102*time.Second) || !tracker.host.AnchorWall.Equal(jump) {
		t.Fatalf("capture anchor did not refresh: %+v", tracker.host)
	}
	if step, err := tracker.observe(clockSample{uint64(103 * time.Second), jump.Add(time.Second)}); err != nil || step != nil || tracker.changes != 1 {
		t.Fatalf("steady sampling created another discontinuity: %+v, %v", step, err)
	}
	if tracker.host.AnchorMonoNS != uint64(103*time.Second) || !tracker.host.AnchorWall.Equal(jump.Add(time.Second)) {
		t.Fatalf("current sample was not used: %+v", tracker.host)
	}
}

func TestClockTrackerDetectsBackwardRealtimeStep(t *testing.T) {
	base := time.Date(2026, 9, 27, 15, 0, 0, 0, time.UTC)
	tracker := newClockTracker(model.Host{AnchorMonoNS: 100, AnchorWall: base})
	step, err := tracker.observe(clockSample{bootNS: 200, wall: base.Add(-time.Minute)})
	if err != nil || step == nil || step.OffsetChangeNS >= 0 {
		t.Fatalf("backward realtime step missing: %+v, %v", step, err)
	}
}

func TestClockTrackerDoesNotMistakeLinuxSuspendForRealtimeStep(t *testing.T) {
	base := time.Date(2026, 9, 28, 7, 0, 0, 0, time.UTC)
	tracker := newClockTracker(model.Host{ClockSource: "boottime", AnchorMonoNS: uint64(time.Hour), AnchorWall: base})
	resume := clockSample{bootNS: uint64(2 * time.Hour), wall: base.Add(time.Hour)}
	if step, err := tracker.observe(resume); err != nil || step != nil || tracker.changes != 0 {
		t.Fatalf("equal BOOTTIME and REALTIME advances were mistaken for a step: %+v, %v", step, err)
	}
	if !tracker.host.AnchorWall.Equal(resume.wall) || tracker.host.AnchorMonoNS != resume.bootNS {
		t.Fatalf("resume did not refresh UTC anchor: %+v", tracker.host)
	}
}

func TestClockTrackerDoesNotClassifyGradualOffsetDriftAsStep(t *testing.T) {
	base := time.Date(2026, 9, 27, 15, 0, 0, 0, time.UTC)
	tracker := newClockTracker(model.Host{AnchorMonoNS: uint64(100 * time.Second), AnchorWall: base})
	for i := 1; i <= 3000; i++ {
		boot := uint64(time.Duration(100+i) * time.Second)
		wall := base.Add(time.Duration(i)*time.Second + time.Duration(i)*time.Millisecond)
		if step, err := tracker.observe(clockSample{bootNS: boot, wall: wall}); err != nil || step != nil {
			t.Fatalf("gradual drift created a discontinuity at sample %d: %+v, %v", i, step, err)
		}
	}
	if tracker.changes != 0 {
		t.Fatalf("gradual drift was classified as a local step: %d", tracker.changes)
	}
}

func TestClockTrackerRejectsBackwardBootTime(t *testing.T) {
	tracker := newClockTracker(model.Host{AnchorMonoNS: 100, AnchorWall: time.Date(2026, 9, 27, 15, 0, 0, 0, time.UTC)})
	if _, err := tracker.observe(clockSample{bootNS: 99, wall: tracker.last.wall.Add(time.Second)}); err == nil {
		t.Fatal("backward BOOTTIME would corrupt recorder ordering")
	}
}
