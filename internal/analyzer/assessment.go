package analyzer

import (
	"fmt"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

// Assessment is the shared, unstyled verdict for JSON and terminal reports.
// Workload signals and evidence quality are separate. Codes and counters let
// callers interpret the result without parsing human text.
type Assessment struct {
	Code          string             `json:"code"`
	Severity      string             `json:"severity"`
	Title         string             `json:"title"`
	SignalState   string             `json:"signal_state"`
	EvidenceState string             `json:"evidence_state"`
	Signals       string             `json:"signal_summary"`
	Evidence      string             `json:"evidence_summary"`
	Observed      ObservedSignals    `json:"observed_lower_bounds"`
	Reasons       []CoverageReason   `json:"coverage_reasons"`
	Diagnostics   []CoverageReason   `json:"lifetime_diagnostics"`
	Highlights    []LatencyHighlight `json:"latency_highlights"`
}
type ObservedSignals struct {
	Slow        uint64 `json:"slow"`
	Critical    uint64 `json:"critical_latency,omitempty"`
	Retransmits uint64 `json:"tcp_retransmits"`
	Resets      uint64 `json:"tcp_resets"`
	OOMVictims  uint64 `json:"oom_victims"`
}
type CoverageReason struct {
	Code          string        `json:"code"`
	Severity      string        `json:"severity"`
	Scope         string        `json:"scope"`
	Sensor        string        `json:"sensor,omitempty"`
	Counter       string        `json:"counter,omitempty"`
	Count         uint64        `json:"count,omitempty"`
	LifetimeCount *uint64       `json:"lifetime_count,omitempty"`
	Limited       bool          `json:"limits_evidence"`
	Title         string        `json:"title"`
	Explanation   string        `json:"explanation"`
	Evidence      []EvidenceRef `json:"evidence"`
}
type LatencyHighlight struct {
	Family      string `json:"family"`
	LatencyNS   uint64 `json:"latency_ns"`
	ThresholdNS uint64 `json:"threshold_ns"`
	EventIndex  int    `json:"event_index"`
}

func assess(r Report) Assessment {
	a := Assessment{Code: "no_anomalies_observed", Severity: "info", Title: "NO ANOMALIES OBSERVED", SignalState: "clear", EvidenceState: "complete", Signals: "Signals: no anomalies found in the measured observations.", Evidence: "Evidence: no collection gaps reported in captured aggregate intervals.", Reasons: []CoverageReason{}, Diagnostics: []CoverageReason{}, Highlights: []LatencyHighlight{}}
	activity, monitored := uint64(0), uint64(0)
	window := r.Manifest.EndMonoNS - r.Manifest.StartMonoNS
	details := map[string]uint64{}
	worst := map[string]LatencyHighlight{}
	for i, e := range r.Timeline {
		switch e.Type {
		case "oom", "tcp_retransmit", "tcp_reset":
			details[e.Type]++
		case "block_io", "scheduler":
			if e.LatencyNS > 0 {
				details[e.Type]++
				if e.LatencyNS > worst[e.Type].LatencyNS {
					threshold := r.Manifest.Settings.BlockThresholdNS
					if e.Type == "scheduler" {
						threshold = r.Manifest.Settings.SchedulerThresholdNS
					}
					worst[e.Type] = LatencyHighlight{e.Type, e.LatencyNS, threshold, i}
				}
			}
		}
	}
	add := func(n CoverageReason) { a.Reasons = append(a.Reasons, n) }
	for i, s := range r.Signals {
		if s.State == "disabled" {
			continue
		}
		activity += s.Count
		monitored += s.CoveredNS
		switch s.Family {
		case "block_io", "scheduler":
			critical := criticalCount(r, s)
			a.Observed.Slow += max(s.Anomalies, details[s.Family], critical)
			a.Observed.Critical += critical
		case "tcp":
			a.Observed.Retransmits = max(s.Retransmits, details["tcp_retransmit"])
			a.Observed.Resets = max(s.Resets, details["tcp_reset"])
		case "oom":
			a.Observed.OOMVictims = max(s.Count, details["oom"])
		}
		if h, ok := worst[s.Family]; ok {
			a.Highlights = append(a.Highlights, h)
		}
		refs := []EvidenceRef{{"aggregate", i, fmt.Sprintf("state=%s covered_ns=%d", s.State, s.CoveredNS)}}
		if s.State != "healthy" {
			add(CoverageReason{Code: "sensor_unavailable", Severity: "warning", Scope: "window", Sensor: s.Family, Limited: true, Title: sensorName(s.Family) + " coverage unavailable or incomplete", Explanation: "The subsystem cannot be assessed for the full window. Sensor state: " + s.State + ". " + s.Reason, Evidence: refs})
		} else if s.CoveredNS == 0 {
			add(CoverageReason{Code: "no_metric_intervals", Severity: "warning", Scope: "window", Sensor: s.Family, Limited: true, Title: sensorName(s.Family) + ": no complete metric intervals", Explanation: "No aggregate interval was retained for this subsystem; zero counts cannot establish absence of anomalies.", Evidence: refs})
		} else if tolerance := coverageTolerance(r.Manifest); window > tolerance && s.CoveredNS < window && window-s.CoveredNS > tolerance {
			// Up to two partial boundary intervals are excluded by snapshot selection.
			add(CoverageReason{Code: "metric_gap", Severity: "warning", Scope: "window", Sensor: s.Family, Limited: true, Title: sensorName(s.Family) + ": aggregate coverage is shorter than the window", Explanation: fmt.Sprintf("%.1fs of metrics for a %.1fs window. Some activity cannot be assessed.", float64(s.CoveredNS)/1e9, float64(window)/1e9), Evidence: refs})
		}
		var life model.Counters
		lifeIndex := -1
		for j, h := range r.Manifest.Health.Sensors {
			if h.Name == s.Family {
				life, lifeIndex = h.Loss, j
				break
			}
		}
		current, historical := model.CounterNotes(s.Family, s.Loss), model.CounterNotes(s.Family, life)
		for _, n := range current {
			reason := CoverageReason{Code: n.Counter, Severity: "warning", Scope: "window", Sensor: s.Family, Counter: n.Counter, Count: n.Value, Limited: true, Title: n.Title, Explanation: n.Explanation, Evidence: []EvidenceRef{{"aggregate", i, fmt.Sprintf("%s=%d (captured aggregate intervals)", n.Counter, n.Value)}}}
			for _, old := range historical {
				if old.Counter == n.Counter {
					value := old.Value
					reason.LifetimeCount = &value
				}
			}
			add(reason)
		}
		for _, n := range historical {
			a.Diagnostics = append(a.Diagnostics, CoverageReason{Code: n.Counter, Severity: "info", Scope: "lifetime", Sensor: s.Family, Counter: n.Counter, Count: n.Value, Title: n.Title, Explanation: n.Explanation + " This is a daemon lifetime total, not an additional window loss.", Evidence: []EvidenceRef{{"sensor_health", lifeIndex, fmt.Sprintf("%s=%d (daemon lifetime)", n.Counter, n.Value)}}})
		}
	}
	// Trigger evidence may outlive its source intervals after retention eviction.
	// Keep it separate from window totals and never count it twice.
	triggerIntervalsMissing := false
	if incident := r.Manifest.AutoIncident; incident != nil {
		for _, trigger := range incident.Triggers {
			if trigger.FirstIntervalStartNS < r.Manifest.StartMonoNS {
				triggerIntervalsMissing = true
			}
		}
		if triggerIntervalsMissing {
			add(CoverageReason{Code: "trigger_intervals_missing", Severity: "warning", Scope: "trigger", Limited: true, Title: "Some trigger intervals precede retained evidence", Explanation: "Automatic trigger metadata preserves the reason for recording. Its counts are not added to captured-window totals.", Evidence: []EvidenceRef{{Kind: "manifest", Value: "auto_incident"}}})
		}
	}
	n := a.Observed
	if n.OOMVictims > 0 {
		a.Code, a.Severity, a.Title, a.SignalState = "oom_victims_observed", "critical", "OOM VICTIMS OBSERVED", "critical"
		a.Signals = "Signals: at least " + quantity(n.OOMVictims, "out-of-memory victim event", "out-of-memory victim events") + "."
	} else if n.Critical > 0 {
		a.Code, a.Severity, a.Title, a.SignalState = "critical_latency_observed", "critical", "CRITICAL LATENCY OBSERVED", "critical"
		a.Signals = "Signals: at least " + quantity(n.Critical, "critical latency observation", "critical latency observations") + " among " + quantity(n.Slow, "slow observation", "slow observations") + "."
		a.Signals += fmt.Sprintf(" TCP: %d retransmits, %d reset observations.", n.Retransmits, n.Resets)
	} else if n.Slow > 0 || n.Retransmits > 0 || n.Resets > 0 {
		a.Code, a.Severity, a.Title, a.SignalState = "signals_to_review", "warning", "SIGNALS TO REVIEW", "review"
		a.Signals = "Signals: at least " + quantity(n.Slow, "slow observation", "slow observations") + ", " + quantity(n.Retransmits, "TCP retransmit", "TCP retransmits") + ", " + quantity(n.Resets, "reset observation", "reset observations") + "."
	} else if activity == 0 {
		a.Code, a.Title, a.SignalState = "no_activity", "NO ACTIVITY TO ASSESS", "no_activity"
		a.Signals = "Signals: no activity measured; I/O and scheduler latency cannot be assessed."
	}
	if r.Manifest.AutoIncident != nil && a.SignalState != "critical" {
		a.Code, a.Severity, a.Title, a.SignalState = "critical_trigger_detected", "critical", "CRITICAL TRIGGER DETECTED · EVIDENCE LIMITED", "critical"
		a.Signals = "Signals: automatic trigger metadata confirms critical latency or OOM; triggering observations are absent from retained evidence. Captured-window counts exclude those triggers."
		if !triggerIntervalsMissing {
			add(CoverageReason{Code: "trigger_evidence_not_retained", Severity: "warning", Scope: "trigger", Limited: true, Title: "Critical trigger observations are absent from retained evidence", Explanation: "The automatic trigger metadata confirms why recording started, but retained aggregates and details do not show those critical observations. Trigger counts are not added to captured-window totals.", Evidence: []EvidenceRef{{Kind: "manifest", Value: "auto_incident"}}})
		}
	}
	// Details from one subsystem do not provide attribution for another.
	for i, s := range r.Signals {
		if s.State == "disabled" {
			continue
		}
		anomalies, retained := s.Anomalies, details[s.Family]
		if s.Family == "tcp" {
			anomalies, retained = s.Retransmits+s.Resets, details["tcp_retransmit"]+details["tcp_reset"]
		}
		if s.Family == "oom" {
			anomalies = s.Count
		}
		if anomalies > 0 && retained == 0 {
			add(CoverageReason{Code: "anomaly_details_missing", Severity: "warning", Scope: "window", Sensor: s.Family, Count: anomalies, Limited: true, Title: sensorName(s.Family) + ": anomalies counted, but no individual details retained", Explanation: "The aggregates show activity to review; process attribution and individual events are unavailable.", Evidence: []EvidenceRef{{"aggregate", i, fmt.Sprintf("anomalies=%d retained_details=0", anomalies)}}})
		}
	}
	h := r.Manifest.Health
	var missingEndpoints uint64
	var endpointRefs []EvidenceRef
	for i, e := range r.Timeline {
		if (e.Type == "tcp_reset" || e.Type == "tcp_retransmit") && (e.SourceIP == "" || e.DestinationIP == "") {
			missingEndpoints++
			if len(endpointRefs) < 5 {
				endpointRefs = append(endpointRefs, EvidenceRef{"event", i, e.Type + " endpoint metadata unavailable"})
			}
		}
	}
	if missingEndpoints > 0 {
		add(CoverageReason{Code: "tcp_endpoints_unavailable", Severity: "warning", Scope: "retained_events", Sensor: "tcp", Count: missingEndpoints, Limited: true, Title: quantity(missingEndpoints, "TCP event lacks endpoint metadata", "TCP events lack endpoint metadata"), Explanation: "These observations were retained, but their peer addresses cannot be identified from the capture. Older sensors collected only socket metadata and missed the packet tuple of socket-less reset responses. Process ownership is separately outside the current sensor's scope.", Evidence: endpointRefs})
	}
	if r.Manifest.StartMonoNS > r.Manifest.RequestedStartMonoNS {
		missing := r.Manifest.StartMonoNS - r.Manifest.RequestedStartMonoNS
		requested := r.Manifest.EndMonoNS - r.Manifest.RequestedStartMonoNS
		explanation := fmt.Sprintf("%s of the requested %s is unavailable. The report covers only the retained window.", time.Duration(missing).Round(time.Millisecond), time.Duration(requested).Round(time.Millisecond))
		if start := r.Manifest.RecordingStartMonoNS; start > r.Manifest.RequestedStartMonoNS {
			explanation += fmt.Sprintf(" The recorder had not started for the first %s of the request.", time.Duration(start-r.Manifest.RequestedStartMonoNS).Round(time.Millisecond))
		}
		add(CoverageReason{Code: "history_truncated", Severity: "warning", Scope: "requested_window", Limited: true, Title: "Requested history was not fully retained", Explanation: explanation, Evidence: []EvidenceRef{{"manifest", 0, fmt.Sprintf("missing_history_ns=%d", missing)}}})
	}
	if h.IngressDrops+h.RecorderDrops > 0 {
		add(CoverageReason{Code: "userspace_drops", Severity: "warning", Scope: "lifetime_window_unknown", Count: h.IngressDrops + h.RecorderDrops, Limited: true, Title: "Some observations were dropped during this daemon run", Explanation: fmt.Sprintf("%d event details were rejected by userspace ingress; %d observations could not be retained by the recorder. These counters are lifetime-only; occurrence in this window is unknown.", h.IngressDrops, h.RecorderDrops), Evidence: []EvidenceRef{{"health", 0, fmt.Sprintf("ingress_drops=%d recorder_drops=%d (daemon lifetime)", h.IngressDrops, h.RecorderDrops)}}})
	}
	if len(a.Reasons) > 0 {
		a.EvidenceState = "limited"
		a.Evidence = "Evidence incomplete: " + a.Reasons[0].Title + "."
		if len(a.Reasons) > 1 {
			a.Evidence += " " + quantity(uint64(len(a.Reasons)-1), "other collection note below", "other collection notes below") + "."
		}
		if a.SignalState == "clear" {
			a.Code, a.Severity = "no_anomalies_evidence_limited", "warning"
			a.Title += " · EVIDENCE LIMITED"
		} else if a.SignalState == "no_activity" {
			a.Code, a.Severity, a.Title = "insufficient_evidence", "warning", "INSUFFICIENT EVIDENCE"
		}
		if monitored == 0 && len(r.Timeline) == 0 {
			a.EvidenceState = "unavailable"
		}
	} else if monitored == 0 {
		a.Evidence = "Evidence: no complete aggregate intervals available."
	}
	return a
}
func quantity(n uint64, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}
func sensorName(s string) string {
	switch s {
	case "block_io":
		return "Block I/O"
	case "scheduler":
		return "Scheduler"
	case "tcp":
		return "TCP"
	case "oom":
		return "OOM"
	default:
		return s
	}
}

func coverageTolerance(m model.Manifest) uint64 {
	poll := m.Settings.PollIntervalNS
	if poll == 0 {
		poll = model.LegacyPollIntervalNS
	}
	if poll > ^uint64(0)/2 {
		return ^uint64(0)
	}
	return 2 * poll
}

func criticalThreshold(s model.RecordingSettings, family string) uint64 {
	switch family {
	case "block_io":
		return s.BlockCriticalNS
	case "scheduler":
		return s.SchedulerCriticalNS
	default:
		return 0
	}
}

func criticalCount(r Report, s Summary) uint64 {
	var retained uint64
	if threshold := criticalThreshold(r.Manifest.Settings, s.Family); threshold > 0 {
		for _, e := range r.Timeline {
			if e.Type == s.Family && e.LatencyNS >= threshold {
				retained++
			}
		}
	}
	return max(s.Critical, retained)
}
