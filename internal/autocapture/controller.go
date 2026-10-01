// Package autocapture owns automatic incident scheduling and bounded storage.
package autocapture

import (
	"slices"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

// Controller is owned by the recorder loop. It keeps at most the current window
// and one waiting window; file writes never stop trigger detection.
type Controller struct {
	config       config.Config
	health       model.AutoCaptureHealth
	current      *model.AutoIncident
	next         *model.AutoIncident
	currentReady uint64
	nextReady    uint64
	writing      bool
	writingEnd   uint64
	lastSavedEnd uint64
}

func New(c config.Config, available []string) *Controller {
	sources := []string{}
	for _, s := range c.AutoCapture.Sensors {
		if slices.Contains(c.Enabled, s) && slices.Contains(available, s) {
			sources = append(sources, s)
		}
	}
	return &Controller{config: c, health: model.AutoCaptureHealth{Directory: c.AutoCapture.Directory, Sensors: sources}}
}

func (c *Controller) Health() *model.AutoCaptureHealth {
	h := c.health
	h.Sensors = append([]string(nil), h.Sensors...)
	h.State = "armed"
	if len(h.Sensors) == 0 {
		h.State = "inactive"
	}
	if c.current != nil {
		h.State = "pending"
		h.PendingUntilNS = c.current.EndMonoNS
	}
	if c.writing {
		h.State = "writing"
	}
	return &h
}

func (c *Controller) Unavailable(family string) {
	c.health.Sensors = slices.DeleteFunc(c.health.Sensors, func(s string) bool { return s == family })
}

func (c *Controller) Observe(m model.Metric, now uint64) {
	if m.EndMonoNS <= m.StartMonoNS || !slices.Contains(c.health.Sensors, m.Family) {
		return
	}
	n, threshold, reason := m.Critical, uint64(0), "critical_latency"
	switch m.Family {
	case "block_io":
		threshold = uint64(c.config.BlockCritical)
	case "scheduler":
		threshold = uint64(c.config.SchedulerCritical)
	case "oom":
		n, reason = m.Count, "oom_victim"
	default:
		return
	}
	if n == 0 {
		return
	}
	c.health.Detected += n
	incident := c.current
	if incident == nil {
		c.current = c.newIncident(now)
		incident = c.current
		c.health.Coalesced += n - 1
	} else if now > incident.EndMonoNS {
		if c.next == nil {
			c.next = c.newIncident(now)
			c.health.Coalesced += n - 1
		} else {
			// A busy writer can delay the next file. Merge further windows into
			// the waiting one so trigger evidence is retained with bounded state.
			if end := now + uint64(c.config.AutoCapture.After); end > c.next.EndMonoNS {
				c.next.EndMonoNS = end
				c.next.AfterNS = end - c.next.DetectedMonoNS
				c.nextReady = 0
			}
			c.health.Coalesced += n
		}
		incident = c.next
	} else {
		c.health.Coalesced += n
	}
	for i := range incident.Triggers {
		r := &incident.Triggers[i]
		if r.Family == m.Family {
			r.Count += n
			r.LastIntervalEndNS = m.EndMonoNS
			return
		}
	}
	incident.Triggers = append(incident.Triggers, model.AutoTrigger{Family: m.Family, Reason: reason, Count: n, ThresholdNS: threshold, FirstIntervalStartNS: m.StartMonoNS, LastIntervalEndNS: m.EndMonoNS})
}

func (c *Controller) newIncident(now uint64) *model.AutoIncident {
	return &model.AutoIncident{DetectedMonoNS: now, EndMonoNS: now + uint64(c.config.AutoCapture.After), BeforeNS: uint64(c.config.AutoCapture.Before), AfterNS: uint64(c.config.AutoCapture.After)}
}

func (c *Controller) Deadline() (uint64, bool) {
	if c.current == nil || c.writing {
		return 0, false
	}
	return c.current.EndMonoNS, true
}

// CollectedThrough remembers the first complete poll past each deadline. A
// busy snapshot writer must not extend the window on every later retry.
func (c *Controller) CollectedThrough(end uint64) {
	if c.current != nil && c.currentReady == 0 && end >= c.current.EndMonoNS {
		c.currentReady = end
	}
	if c.next != nil && c.nextReady == 0 && end >= c.next.EndMonoNS {
		c.nextReady = end
	}
}

func (c *Controller) Begin() (model.AutoIncident, uint64) {
	v := *c.current
	v.Triggers = append([]model.AutoTrigger(nil), v.Triggers...)
	// Aggregates are indivisible intervals. Include the interval collected at
	// the deadline so it cannot fall between two published files.
	if c.currentReady > v.EndMonoNS {
		v.EndMonoNS = c.currentReady
		v.AfterNS = c.currentReady - v.DetectedMonoNS
	}
	start := uint64(0)
	if v.DetectedMonoNS > v.BeforeNS {
		start = v.DetectedMonoNS - v.BeforeNS
	}
	if start < c.lastSavedEnd {
		start = c.lastSavedEnd
	}
	// Include a complete trigger aggregate if it straddles the previous file's
	// end. This permits only the boundary interval to overlap, not the full lookback.
	boundary := start
	for _, trigger := range v.Triggers {
		if trigger.FirstIntervalStartNS < boundary && trigger.LastIntervalEndNS >= boundary {
			start = min(start, trigger.FirstIntervalStartNS)
		}
	}
	c.current, c.next = c.next, nil
	c.currentReady, c.nextReady = c.nextReady, 0
	c.writing = true
	c.writingEnd = v.EndMonoNS
	return v, start
}

func (c *Controller) Finish(path string, savedAt time.Time, err error) {
	c.writing = false
	if path != "" {
		// Store returns a path only after publication. Rotation can fail later;
		// that error must not make the next incident repeat this saved window.
		c.health.Saved++
		c.lastSavedEnd = c.writingEnd
		c.health.LastPath, c.health.LastSavedAt = path, savedAt
	}
	c.writingEnd = 0
	if err != nil {
		c.health.Failures++
		c.health.LastError = err.Error()
		return
	}
	c.health.LastError = ""
}
