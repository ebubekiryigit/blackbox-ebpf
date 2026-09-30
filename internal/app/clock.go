package app

import (
	"fmt"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

// Ignore normal clock-sampling jitter and gradual clock slewing.
const clockDiscontinuityThreshold = 2 * time.Second

type clockSample struct {
	bootNS uint64
	wall   time.Time
}

// clockTracker belongs to the recording loop. Every sample refreshes the
// presentation anchor; only the latest significant offset change is retained.
type clockTracker struct {
	host    model.Host
	last    clockSample
	changes uint64
	latest  *model.ClockDiscontinuity
}

func newClockTracker(host model.Host) clockTracker {
	return clockTracker{host: host, last: clockSample{host.AnchorMonoNS, host.AnchorWall}}
}

func (t *clockTracker) observe(sample clockSample) (*model.ClockDiscontinuity, error) {
	if sample.bootNS < t.last.bootNS {
		return nil, fmt.Errorf("CLOCK_BOOTTIME moved backward from %d to %d", t.last.bootNS, sample.bootNS)
	}
	bootElapsed := time.Duration(sample.bootNS - t.last.bootNS)
	wallElapsed := sample.wall.Sub(t.last.wall)
	change := wallElapsed - bootElapsed
	var discontinuity *model.ClockDiscontinuity
	if change > clockDiscontinuityThreshold || change < -clockDiscontinuityThreshold {
		step := model.ClockDiscontinuity{
			DetectedBootNS: sample.bootNS,
			DetectedAt:     sample.wall.UTC(),
			OffsetChangeNS: int64(change),
		}
		t.changes++
		t.latest = &step
		discontinuity = &step
	}
	t.last = sample
	t.host.AnchorMonoNS, t.host.AnchorWall = sample.bootNS, sample.wall.UTC()
	return discontinuity, nil
}
