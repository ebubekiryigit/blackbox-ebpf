package model

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func validIncident() *AutoIncident {
	return &AutoIncident{
		DetectedMonoNS: 100,
		EndMonoNS:      110,
		BeforeNS:       60,
		AfterNS:        10,
		Triggers:       []AutoTrigger{{Family: "oom", Reason: "oom_victim", Count: 1, FirstIntervalStartNS: 99, LastIntervalEndNS: 100}},
	}
}

func TestAutoIncidentRejectsInconsistentTriggerMetadata(t *testing.T) {
	if !(*AutoIncident)(nil).Valid(110) || !validIncident().Valid(110) {
		t.Fatal("valid optional incident metadata rejected")
	}
	for _, tc := range []struct {
		name   string
		change func(*AutoIncident)
	}{
		{"zero history", func(a *AutoIncident) { a.BeforeNS = 0 }},
		{"detection after end", func(a *AutoIncident) { a.DetectedMonoNS = 111 }},
		{"wrong end", func(a *AutoIncident) { a.EndMonoNS = 109 }},
		{"wrong after", func(a *AutoIncident) { a.AfterNS = 9 }},
		{"no triggers", func(a *AutoIncident) { a.Triggers = nil }},
		{"too many triggers", func(a *AutoIncident) { a.Triggers = append(a.Triggers, a.Triggers[0], a.Triggers[0], a.Triggers[0]) }},
		{"duplicate family", func(a *AutoIncident) { a.Triggers = append(a.Triggers, a.Triggers[0]) }},
		{"zero count", func(a *AutoIncident) { a.Triggers[0].Count = 0 }},
		{"empty interval", func(a *AutoIncident) { a.Triggers[0].FirstIntervalStartNS = 100 }},
		{"interval after capture", func(a *AutoIncident) { a.Triggers[0].LastIntervalEndNS = 111 }},
		{"unknown family", func(a *AutoIncident) { a.Triggers[0].Family = "tcp" }},
		{"oom with threshold", func(a *AutoIncident) { a.Triggers[0].ThresholdNS = 1 }},
		{"oom wrong reason", func(a *AutoIncident) { a.Triggers[0].Reason = "critical_latency" }},
		{"block without threshold", func(a *AutoIncident) { a.Triggers[0].Family, a.Triggers[0].Reason = "block_io", "critical_latency" }},
		{"scheduler wrong reason", func(a *AutoIncident) { a.Triggers[0].Family, a.Triggers[0].ThresholdNS = "scheduler", 20 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := validIncident()
			tc.change(a)
			if a.Valid(110) {
				t.Fatal("invalid trigger metadata accepted")
			}
		})
	}
	for _, family := range []string{"block_io", "scheduler"} {
		a := validIncident()
		a.Triggers[0].Family = family
		a.Triggers[0].Reason = "critical_latency"
		a.Triggers[0].ThresholdNS = 20
		if !a.Valid(110) {
			t.Fatalf("valid %s critical trigger rejected", family)
		}
	}
}

func TestCounterNotesExplainCoverageWithoutInventingCause(t *testing.T) {
	if notes := CounterNotes("block_io", Counters{}); len(notes) != 0 {
		t.Fatalf("zero counters produced notes: %+v", notes)
	}
	for _, tc := range []struct {
		sensor, counter, title string
		loss                   Counters
	}{
		{"block_io", "unmatched_completions", "1 I/O completion could not be timed", Counters{Unmatched: 1}},
		{"scheduler", "unmatched_completions", "2 completions had no matching start record", Counters{Unmatched: 2}},
		{"block_io", "tracking_failures", "1 start record could not be saved", Counters{TrackingFailures: 1}},
		{"block_io", "ring_reserve_failures", "2 event details could not enter the kernel buffer", Counters{RingFailures: 2}},
		{"tcp", "detail_suppressed", "1 event detail skipped by the rate limit", Counters{Suppressed: 1}},
		{"oom", "detail_decode_failures", "2 event details could not be decoded", Counters{DecodeFailures: 2}},
	} {
		t.Run(tc.sensor+"/"+tc.counter, func(t *testing.T) {
			notes := CounterNotes(tc.sensor, tc.loss)
			if len(notes) != 1 || notes[0].Counter != tc.counter || notes[0].Title != tc.title || notes[0].Explanation == "" {
				t.Fatalf("coverage note lost meaning: %+v", notes)
			}
		})
	}
}

func TestFormatAndClockContracts(t *testing.T) {
	if err := CheckReadableFormat(FormatVersion); err != nil {
		t.Fatal(err)
	}
	for _, format := range []int{0, FormatVersion + 1} {
		var unsupported *UnsupportedFormatError
		if err := CheckReadableFormat(format); !errors.As(err, &unsupported) || unsupported.Found != format || !strings.Contains(err.Error(), "compatible analyzer") {
			t.Fatalf("format %d did not produce an actionable error: %v", format, err)
		}
	}
	var histogram Histogram
	histogram[0], histogram[len(histogram)-1] = 2, 3
	if histogram.Count() != 5 {
		t.Fatal("histogram buckets were not counted")
	}
	anchor := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	host := Host{AnchorMonoNS: 100, AnchorWall: anchor}
	if got := host.Wall(125); !got.Equal(anchor.Add(25 * time.Nanosecond)) {
		t.Fatalf("monotonic wall conversion changed: %s", got)
	}
}
