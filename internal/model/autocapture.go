package model

import "time"

// AutoIncident describes detection from aggregate intervals, not an exact event
// timestamp. At most one reason per supported trigger family is retained.
type AutoIncident struct {
	DetectedMonoNS uint64        `json:"detected_mono_ns"`
	EndMonoNS      uint64        `json:"end_mono_ns"`
	BeforeNS       uint64        `json:"before_ns"`
	AfterNS        uint64        `json:"after_ns"`
	Triggers       []AutoTrigger `json:"triggers"`
}

type AutoTrigger struct {
	Family               string `json:"family"`
	Reason               string `json:"reason"`
	Count                uint64 `json:"count"`
	ThresholdNS          uint64 `json:"threshold_ns,omitempty"`
	FirstIntervalStartNS uint64 `json:"first_interval_start_ns"`
	LastIntervalEndNS    uint64 `json:"last_interval_end_ns"`
}

type AutoCaptureHealth struct {
	State          string    `json:"state"`
	Directory      string    `json:"directory"`
	Sensors        []string  `json:"sensors"`
	Detected       uint64    `json:"detected"`
	Coalesced      uint64    `json:"coalesced"`
	Saved          uint64    `json:"saved"`
	Failures       uint64    `json:"failures"`
	LastPath       string    `json:"last_path,omitempty"`
	LastSavedAt    time.Time `json:"last_saved_at,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	PendingUntilNS uint64    `json:"pending_until_ns,omitempty"`
	PendingForNS   uint64    `json:"pending_for_ns,omitempty"`
}

// Valid accepts only bounded, internally consistent trigger metadata. It is
// optional for historical captures and does not change the capture discriminator.
func (a *AutoIncident) Valid(end uint64) bool {
	if a == nil {
		return true
	}
	if a.BeforeNS == 0 || a.DetectedMonoNS > a.EndMonoNS || a.EndMonoNS != end || a.EndMonoNS-a.DetectedMonoNS != a.AfterNS || len(a.Triggers) == 0 || len(a.Triggers) > 3 {
		return false
	}
	seen := map[string]bool{}
	for _, t := range a.Triggers {
		if seen[t.Family] || t.Count == 0 || t.FirstIntervalStartNS >= t.LastIntervalEndNS || t.LastIntervalEndNS > a.EndMonoNS {
			return false
		}
		seen[t.Family] = true
		switch t.Family {
		case "block_io", "scheduler":
			if t.Reason != "critical_latency" || t.ThresholdNS == 0 {
				return false
			}
		case "oom":
			if t.Reason != "oom_victim" || t.ThresholdNS != 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
