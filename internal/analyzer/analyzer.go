// Package analyzer is deterministic and has no host, sensor or socket dependencies.
package analyzer

import (
	"fmt"
	"sort"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

// Coincidence is an analysis rule, not proof of causation.
const coincidenceWindow = time.Second

type EvidenceRef struct {
	Kind  string `json:"kind"`
	Index int    `json:"index"`
	Value string `json:"value"`
}
type Finding struct {
	Category string        `json:"category"`
	Severity string        `json:"severity"`
	Summary  string        `json:"summary"`
	Evidence []EvidenceRef `json:"evidence"`
}
type Summary struct {
	BookkeepingCompletions uint64          `json:"bookkeeping_completions,omitempty"`
	State                  string          `json:"coverage_state"`
	Reason                 string          `json:"coverage_reason,omitempty"`
	Family                 string          `json:"family"`
	Available              bool            `json:"available"`
	Histogram              model.Histogram `json:"histogram"`
	Count                  uint64          `json:"count"`
	Anomalies              uint64          `json:"anomalies"`
	Critical               uint64          `json:"critical_latency,omitempty"`
	Retransmits            uint64          `json:"retransmits"`
	Resets                 uint64          `json:"resets"`
	Loss                   model.Counters  `json:"loss"`
	CoveredNS              uint64          `json:"covered_ns"`
}
type Process struct {
	Comm    string `json:"comm"`
	TGID    uint32 `json:"tgid"`
	StartNS uint64 `json:"start_ns"`
	Details int    `json:"details"`
}
type Report struct {
	Assessment Assessment     `json:"assessment"`
	Host       model.Host     `json:"host"`
	Manifest   model.Manifest `json:"manifest"`
	Signals    []Summary      `json:"signals"`
	Timeline   []model.Event  `json:"timeline"`
	Processes  []Process      `json:"processes"`
	Findings   []Finding      `json:"findings"`
}

func Analyze(c model.Capture) Report {
	r := Report{Host: c.Host, Manifest: c.Manifest, Processes: []Process{}, Findings: []Finding{}}
	count := 0
	for _, s := range c.Segments {
		count += len(s.Events)
	}
	r.Timeline = make([]model.Event, 0, count)
	summaries := map[string]*Summary{}
	healthKnown := map[string]bool{}
	for _, f := range model.Families {
		summaries[f] = &Summary{Family: f, State: "unavailable"}
	}
	for _, h := range c.Manifest.Health.Sensors {
		if s := summaries[h.Name]; s != nil {
			healthKnown[h.Name] = true
			s.Available = h.State == "healthy"
			s.State = h.State
			s.Reason = h.Reason
		}
	}
	for _, seg := range c.Segments {
		r.Timeline = append(r.Timeline, seg.Events...)
		for _, m := range seg.Metrics {
			s := summaries[m.Family]
			if s == nil {
				continue
			}
			for i, n := range m.Histogram {
				s.Histogram[i] += n
			}
			// Metrics prove that an older capture collected this subsystem only
			// when no explicit health state was recorded. Never overwrite a saved
			// unavailable/error state with earlier metric availability.
			if !healthKnown[m.Family] {
				s.Available = true
				s.State = "healthy"
			}
			s.Count += m.Count
			s.Anomalies += m.Anomalies
			s.Critical += m.Critical
			s.Retransmits += m.Retransmits
			s.Resets += m.Resets
			s.CoveredNS += m.EndMonoNS - m.StartMonoNS
			s.Loss.RingFailures += m.Loss.RingFailures
			s.Loss.Suppressed += m.Loss.Suppressed
			s.Loss.TrackingFailures += m.Loss.TrackingFailures
			s.Loss.Unmatched += m.Loss.Unmatched
			s.Loss.DecodeFailures += m.Loss.DecodeFailures
			s.BookkeepingCompletions += m.BookkeepingCompletions
		}
	}
	sort.SliceStable(r.Timeline, func(i, j int) bool {
		a, b := r.Timeline[i], r.Timeline[j]
		if a.MonoNS != b.MonoNS {
			return a.MonoNS < b.MonoNS
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.PID < b.PID
	})
	type identity struct {
		comm  string
		tgid  uint32
		start uint64
	}
	ps := map[identity]int{}
	for i, e := range r.Timeline {
		if e.TGID != 0 || e.Comm != "" {
			ps[identity{e.Comm, e.TGID, e.ProcessStartNS}]++
		}
		if e.Type == "oom" {
			r.Findings = append(r.Findings, Finding{"oom", "critical", "An OOM victim was observed.", []EvidenceRef{{"event", i, fmt.Sprintf("victim %s pid=%d", e.Comm, e.PID)}}})
		}
	}
	for k, n := range ps {
		r.Processes = append(r.Processes, Process{k.comm, k.tgid, k.start, n})
	}
	sort.Slice(r.Processes, func(i, j int) bool {
		a, b := r.Processes[i], r.Processes[j]
		if a.Details != b.Details {
			return a.Details > b.Details
		}
		if a.Comm != b.Comm {
			return a.Comm < b.Comm
		}
		if a.TGID != b.TGID {
			return a.TGID < b.TGID
		}
		return a.StartNS < b.StartNS
	})
	for _, f := range model.Families {
		s := *summaries[f]
		r.Signals = append(r.Signals, s)
		if s.State == "disabled" {
			continue
		}
		var direct uint64
		for _, e := range r.Timeline {
			if e.Type == f && e.LatencyNS > 0 || f == "tcp" && (e.Type == "tcp_retransmit" || e.Type == "tcp_reset") || f == "oom" && e.Type == "oom" {
				direct++
			}
		}
		if (s.Anomalies > 0 || s.Critical > 0 || direct > 0) && (f == "block_io" || f == "scheduler") {
			refs := []EvidenceRef{{"aggregate", len(r.Signals) - 1, fmt.Sprintf("%d threshold exceedances", s.Anomalies)}}
			for i, e := range r.Timeline {
				if e.Type == f && e.LatencyNS > 0 {
					refs = append(refs, EvidenceRef{"event", i, fmt.Sprintf("%s pid=%d latency=%s", e.Comm, e.PID, time.Duration(e.LatencyNS))})
					if len(refs) >= 6 {
						break
					}
				}
			}
			severity := "warning"
			if criticalCount(r, s) > 0 {
				severity = "critical"
				if s.Critical > 0 {
					refs = append(refs, EvidenceRef{"aggregate", len(r.Signals) - 1, fmt.Sprintf("%d critical latency observations counted in aggregates (threshold %s)", s.Critical, time.Duration(criticalThreshold(r.Manifest.Settings, f)))})
				}
			}
			r.Findings = append(r.Findings, Finding{f, severity, fmt.Sprintf("Elevated %s latency was observed; this does not identify a root cause.", f), refs})
		}
		if f == "tcp" && (s.Retransmits+s.Resets > 0 || direct > 0) {
			refs := []EvidenceRef{{"aggregate", len(r.Signals) - 1, fmt.Sprintf("retransmits=%d resets=%d", s.Retransmits, s.Resets)}}
			for i, e := range r.Timeline {
				if e.Type == "tcp_retransmit" || e.Type == "tcp_reset" {
					refs = append(refs, EvidenceRef{"event", i, e.Type})
					if len(refs) >= 6 {
						break
					}
				}
			}
			r.Findings = append(r.Findings, Finding{f, "warning", "TCP retransmissions or reset transitions were observed.", refs})
		}
		if f == "oom" && s.Count > 0 && direct == 0 {
			r.Findings = append(r.Findings, Finding{f, "critical", "OOM victims were counted; individual victim details are unavailable.", []EvidenceRef{{"aggregate", len(r.Signals) - 1, fmt.Sprintf("victims=%d", s.Count)}}})
		}
	}
	// Correlate only observed details, within one second and a known process/cgroup.
	for i, e := range r.Timeline {
		if e.Type != "block_io" {
			continue
		}
		for j := i + 1; j < len(r.Timeline); j++ {
			o := r.Timeline[j]
			if o.MonoNS-e.MonoNS > uint64(coincidenceWindow) {
				break
			}
			if o.Type == e.Type {
				continue
			}
			same := e.TGID != 0 && e.TGID == o.TGID && e.ProcessStartNS != 0 && e.ProcessStartNS == o.ProcessStartNS
			same = same || (e.CgroupID != 0 && e.CgroupID == o.CgroupID)
			if same {
				r.Findings = append(r.Findings, Finding{"correlation", "info", "Different kernel signals coincided within one second for the same process or cgroup; timing does not establish causation.", []EvidenceRef{{"event", i, e.Type}, {"event", j, o.Type}}})
				return withLoss(r)
			}
		}
	}
	return withLoss(r)
}
func withLoss(r Report) Report {
	r.Assessment = assess(r)
	h := r.Manifest.Health
	if h.MetadataFailures > 0 {
		r.Findings = append(r.Findings, Finding{"metadata", "info", "Some process metadata could not be resolved; kernel observations were retained.", []EvidenceRef{{"health", 0, fmt.Sprintf("%d unresolved process identities (daemon lifetime)", h.MetadataFailures)}}})
	}
	for _, n := range r.Assessment.Reasons {
		r.Findings = append(r.Findings, Finding{"coverage", n.Severity, n.Title + ". " + n.Explanation, n.Evidence})
	}
	for _, n := range r.Assessment.Diagnostics {
		r.Findings = append(r.Findings, Finding{"coverage", n.Severity, n.Title + ". " + n.Explanation, n.Evidence})
	}
	return r
}
func percentile(h model.Histogram, p uint64) string {
	count := h.Count()
	if count == 0 {
		return "n/a"
	}
	target := count/100*p + (count%100*p+99)/100
	var n uint64
	for i, v := range h {
		n += v
		if n >= target {
			if i == model.HistogramBuckets-1 {
				return fmt.Sprintf(">=%s", time.Duration(model.HistogramMinNS<<(i-1)))
			}
			return fmt.Sprintf("<%s", time.Duration(model.HistogramMinNS<<i))
		}
	}
	return "n/a"
}
