package analyzer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestOOMFindingUsesAggregateOrRetainedCountWithoutAddingThem(t *testing.T) {
	for _, test := range []struct {
		name         string
		aggregate    uint64
		details      int
		disabled     bool
		wantSummary  string
		wantEvidence int
	}{
		{"detail only", 0, 2, false, "At least 2 OOM victim events were observed; 2 individual details were retained.", 2},
		{"aggregate only", 3, 0, false, "OOM victims were counted; individual victim details are unavailable.", 1},
		{"aggregate exceeds details", 5, 2, false, "At least 5 OOM victim events were observed; 2 individual details were retained.", 3},
		{"details exceed aggregate", 1, 2, false, "At least 2 OOM victim events were observed; 2 individual details were retained.", 3},
		{"disabled with retained details", 0, 2, true, "At least 2 OOM victim events were observed; 2 individual details were retained.", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := make([]model.Event, test.details)
			for i := range events {
				events[i] = model.Event{MonoNS: uint64(i + 1), Type: "oom", PID: uint32(i + 1), Comm: "worker"}
			}
			segment := model.Segment{Events: events}
			if test.aggregate > 0 {
				segment.Metrics = []model.Metric{{Family: "oom", Count: test.aggregate}}
			}
			capture := model.Capture{Segments: []model.Segment{segment}}
			if test.disabled {
				capture.Manifest.Health.Sensors = []model.SensorHealth{{Name: "oom", State: "disabled"}}
			}
			report := Analyze(capture)
			var findings []Finding
			for _, finding := range report.Findings {
				if finding.Category == "oom" {
					findings = append(findings, finding)
				}
			}
			if len(findings) != 1 || findings[0].Summary != test.wantSummary || findings[0].Severity != "critical" || len(findings[0].Evidence) != test.wantEvidence {
				t.Fatalf("unexpected OOM findings: %+v", findings)
			}
			for i, ref := range findings[0].Evidence {
				if test.aggregate > 0 {
					if i == 0 {
						if ref.Kind != "aggregate" || ref.Index < 0 || ref.Index >= len(report.Signals) || report.Signals[ref.Index].Family != "oom" {
							t.Fatalf("invalid aggregate reference: %+v", ref)
						}
						continue
					}
					i--
				}
				if ref.Kind != "event" || ref.Index != i {
					t.Fatalf("invalid event reference: %+v", ref)
				}
			}
			encoded, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			var decoded struct {
				Timeline []model.Event `json:"timeline"`
				Findings []Finding     `json:"findings"`
			}
			if err := json.Unmarshal(encoded, &decoded); err != nil || len(decoded.Timeline) != test.details {
				t.Fatalf("JSON report lost timeline details: events=%d error=%v", len(decoded.Timeline), err)
			}
			var jsonOOMFindings int
			for _, finding := range decoded.Findings {
				if finding.Category == "oom" {
					jsonOOMFindings++
				}
			}
			if jsonOOMFindings != 1 {
				t.Fatalf("JSON report contains %d OOM findings", jsonOOMFindings)
			}
		})
	}
}

func TestLargeOOMTimelineKeepsDetailsWithoutGrowingFindings(t *testing.T) {
	const count = 200000
	events := make([]model.Event, count)
	for i := range events {
		events[i] = model.Event{MonoNS: uint64(i + 1), Type: "oom", PID: uint32(i + 1)}
	}
	report := Analyze(model.Capture{Segments: []model.Segment{{Events: events}}})
	if len(report.Timeline) != count {
		t.Fatalf("retained %d events, want %d", len(report.Timeline), count)
	}
	var oomFinding *Finding
	for i := range report.Findings {
		if report.Findings[i].Category == "oom" {
			if oomFinding != nil {
				t.Fatal("more than one OOM finding")
			}
			oomFinding = &report.Findings[i]
		}
	}
	if oomFinding == nil || len(oomFinding.Evidence) != 5 || !strings.Contains(oomFinding.Summary, "200000 OOM victim events") {
		t.Fatalf("unexpected OOM summary: %+v", oomFinding)
	}
}

func BenchmarkAnalyzeOOMJSON(b *testing.B) {
	const count = 200000
	events := make([]model.Event, count)
	for i := range events {
		events[i] = model.Event{MonoNS: uint64(i + 1), Type: "oom", PID: uint32(i + 1)}
	}
	c := model.Capture{Segments: []model.Segment{{Events: events}}}
	b.ReportAllocs()
	b.ResetTimer()
	var size int
	for i := 0; i < b.N; i++ {
		report := Analyze(c)
		encoded, err := json.Marshal(report)
		if err != nil {
			b.Fatal(err)
		}
		size = len(encoded)
	}
	b.StopTimer()
	b.ReportMetric(float64(size), "json_bytes/op")
}
