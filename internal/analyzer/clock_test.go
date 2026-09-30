package analyzer

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestClockDiagnosticUsesCaptureTimeAnchorWithoutLimitingEvidence(t *testing.T) {
	base := time.Date(2026, 9, 28, 7, 0, 0, 0, time.UTC)
	sec := func(n int) uint64 { return uint64(time.Duration(n) * time.Second) }
	change := &model.ClockDiscontinuity{DetectedBootNS: sec(105), DetectedAt: base.Add(-5 * time.Second), OffsetChangeNS: int64(14 * time.Hour)}
	c := model.Capture{
		Host:     model.Host{Hostname: "host", ClockSource: "boottime", AnchorMonoNS: sec(110), AnchorWall: base},
		Manifest: model.Manifest{FormatVersion: model.FormatVersion, StartMonoNS: sec(100), RequestedStartMonoNS: sec(100), EndMonoNS: sec(110), Mode: "ebpf", Health: model.Health{ClockChanges: 1, LastClockChange: change, Sensors: []model.SensorHealth{{Name: "scheduler", State: "healthy"}}}},
		Segments: []model.Segment{{Events: []model.Event{{MonoNS: sec(102), Type: "scheduler", LatencyNS: uint64(30 * time.Millisecond)}}, Metrics: []model.Metric{{Family: "scheduler", StartMonoNS: sec(100), EndMonoNS: sec(110), Count: 1, Anomalies: 1}}}},
	}
	r := Analyze(c)
	if len(r.Assessment.Diagnostics) != 1 || r.Assessment.Diagnostics[0].Code != "clock_discontinuities" {
		t.Fatalf("clock diagnostic missing: %+v", r.Assessment)
	}
	for _, reason := range r.Assessment.Reasons {
		if reason.Code == "clock_discontinuity" {
			t.Fatalf("wall-clock step was treated as lost observation coverage: %+v", reason)
		}
	}
	var out bytes.Buffer
	if err := Render(&out, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Clock changed during this daemon run", "06:59:52.000", "offset change 14h0m0s", "capture-time clock sample"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("report omitted %q:\n%s", want, out.String())
		}
	}
}
