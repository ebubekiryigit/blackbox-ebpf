package analyzer

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/terminal"
)

func TestCriticalLatencyUsesCapturedPolicyAndSurvivesMissingDetails(t *testing.T) {
	cases := []struct {
		name      string
		aggregate uint64
		detail    time.Duration
		threshold uint64
		critical  bool
	}{
		{"aggregate survives suppression", 2, 0, uint64(100 * time.Millisecond), true},
		{"event at threshold", 0, 100 * time.Millisecond, uint64(100 * time.Millisecond), true},
		{"event below threshold", 0, 99 * time.Millisecond, uint64(100 * time.Millisecond), false},
		{"legacy has no critical policy", 0, time.Second, 0, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := quietReport()
			r.Manifest.Settings.SchedulerThresholdNS = uint64(20 * time.Millisecond)
			r.Manifest.Settings.SchedulerCriticalNS = tt.threshold
			r.Signals[1].Anomalies = max(tt.aggregate, 1)
			r.Signals[1].Critical = tt.aggregate
			if tt.detail > 0 {
				r.Timeline = []model.Event{{Type: "scheduler", LatencyNS: uint64(tt.detail), PID: 42}}
			}
			got := assess(r)
			if (got.Severity == "critical") != tt.critical {
				t.Fatalf("incorrect assessment: %+v", got)
			}
			tone, _, _ := signalView(r, r.Signals[1])
			if (tone == terminal.Critical) != tt.critical {
				t.Fatal("signal card contradicts assessment")
			}
			var out bytes.Buffer
			if err := RenderWithOptions(&out, r, RenderOptions{Theme: terminal.Theme{Color: true}}); err != nil {
				t.Fatal(err)
			}
			if tt.critical && !strings.Contains(out.String(), "CRITICAL LATENCY") {
				t.Fatal("critical latency hidden in terminal report")
			}
		})
	}
}

func TestCriticalAggregatesReachOfflineReport(t *testing.T) {
	r := quietReport()
	r.Signals[1].Anomalies, r.Signals[1].Critical = 3, 2
	r.Manifest.Settings.SchedulerCriticalNS = uint64(100 * time.Millisecond)
	segments := []model.Segment{{Metrics: []model.Metric{{Family: "scheduler", StartMonoNS: r.Manifest.StartMonoNS, EndMonoNS: r.Manifest.EndMonoNS, Count: 10, Anomalies: 3, Critical: 2}}}}
	got := Analyze(model.Capture{Manifest: r.Manifest, Segments: segments})
	if got.Signals[1].Critical != 2 || got.Assessment.Severity != "critical" {
		t.Fatalf("critical aggregate discarded: %+v", got)
	}
	found := false
	for _, f := range got.Findings {
		if f.Category == "scheduler" && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Fatal("findings contradict critical assessment")
	}
}
