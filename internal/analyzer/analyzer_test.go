package analyzer

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestMissingCoverageLossAndPIDReuse(t *testing.T) {
	c := model.Capture{Manifest: model.Manifest{FormatVersion: 1, StartMonoNS: 10, EndMonoNS: 100, RequestedStartMonoNS: 0, Health: model.Health{IngressDrops: 2, Sensors: []model.SensorHealth{{Name: "block_io", State: "healthy"}, {Name: "scheduler", State: "unavailable", Reason: "hook absent"}}}}, Segments: []model.Segment{{Events: []model.Event{{MonoNS: 50, Type: "block_io", TGID: 10, Comm: "db", ProcessStartNS: 1}, {MonoNS: 20, Type: "block_io", TGID: 10, Comm: "db", ProcessStartNS: 2}}}}}
	a, b := Analyze(c), Analyze(c)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("analysis is not deterministic")
	}
	if len(a.Processes) != 2 {
		t.Fatal("PID reuse merged identities")
	}
	if a.Timeline[0].MonoNS != 20 {
		t.Fatal("timeline not monotonic")
	}
	var out bytes.Buffer
	_ = Render(&out, a)
	if !strings.Contains(out.String(), "unavailable") || !strings.Contains(out.String(), "incomplete") || !strings.Contains(out.String(), "not fully retained") {
		t.Fatal(out.String())
	}
}
func TestCorrelationRequiresKnownIdentity(t *testing.T) {
	makeCapture := func(start uint64) model.Capture {
		return model.Capture{Segments: []model.Segment{{Events: []model.Event{{MonoNS: 10, Type: "block_io", TGID: 1, ProcessStartNS: 1}, {MonoNS: 20, Type: "scheduler", TGID: 1, ProcessStartNS: start}}}}}
	}
	for _, start := range []uint64{0, 1, 2} {
		r := Analyze(makeCapture(start))
		found := false
		for _, f := range r.Findings {
			if f.Category == "correlation" {
				found = true
			}
		}
		if found != (start == 1) {
			t.Fatalf("false correlation for process start=%d", start)
		}
	}
}

func TestWindowLossIsIndependentOfLifetimeHealth(t *testing.T) {
	c := model.Capture{
		Manifest: model.Manifest{Health: model.Health{Sensors: []model.SensorHealth{{Name: "scheduler", State: "healthy", Loss: model.Counters{Unmatched: 57}}}}},
		Segments: []model.Segment{{Metrics: []model.Metric{{Family: "scheduler", StartMonoNS: 1, EndMonoNS: 2, Loss: model.Counters{Unmatched: 2, Suppressed: 3, DecodeFailures: 1}}, {Family: "scheduler", StartMonoNS: 2, EndMonoNS: 3, Loss: model.Counters{Unmatched: 4, DecodeFailures: 2}}}}},
	}
	r := Analyze(c)
	if s := r.Signals[1]; s.Loss.Unmatched != 6 || s.Loss.Suppressed != 3 || s.Loss.DecodeFailures != 3 {
		t.Fatalf("wrong window counters: %+v", s.Loss)
	}
	if r.Manifest.Health.Sensors[0].Loss.Unmatched != 57 {
		t.Fatal("lifetime counters were overwritten")
	}
	windowWarning, lifetimeInfo := false, false
	for _, f := range r.Findings {
		windowWarning = windowWarning || f.Category == "coverage" && f.Severity == "warning" && strings.Contains(f.Summary, "6 completions")
		lifetimeInfo = lifetimeInfo || f.Category == "coverage" && f.Severity == "info" && strings.Contains(f.Summary, "lifetime")
	}
	if !windowWarning || !lifetimeInfo {
		t.Fatalf("missing distinct coverage findings: %+v", r.Findings)
	}
}

func TestMetricsDoNotOverrideExplicitUnhealthySensorState(t *testing.T) {
	metric := model.Metric{Family: "scheduler", StartMonoNS: 1, EndMonoNS: 2, Count: 1}
	withHealth := model.Capture{
		Manifest: model.Manifest{Health: model.Health{Sensors: []model.SensorHealth{{Name: "scheduler", State: "error", Reason: "reader failed"}}}},
		Segments: []model.Segment{{Metrics: []model.Metric{metric}}},
	}
	report := Analyze(withHealth)
	if signal := report.Signals[1]; signal.Available || signal.State != "error" || signal.Count != 1 {
		t.Fatalf("metric contradicted explicit health: %+v", signal)
	}

	withoutHealth := Analyze(model.Capture{Segments: []model.Segment{{Metrics: []model.Metric{metric}}}})
	if signal := withoutHealth.Signals[1]; !signal.Available || signal.State != "healthy" {
		t.Fatalf("legacy metric availability was lost: %+v", signal)
	}
}

func TestHistogramBoundsIncludingLargeCounters(t *testing.T) {
	for _, tt := range []struct {
		name      string
		histogram model.Histogram
		p         uint64
		want      string
	}{
		{"empty", model.Histogram{}, 99, "n/a"},
		{"first bucket", model.Histogram{100}, 50, "<1ms"},
		{"second bucket", model.Histogram{0, 100}, 95, "<2ms"},
		{"last bucket", model.Histogram{10: 1}, 99, ">=512ms"},
		{"large counter does not overflow", model.Histogram{0, ^uint64(0)}, 99, "<2ms"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := percentile(tt.histogram, tt.p); got != tt.want {
				t.Fatalf("got %s want %s", got, tt.want)
			}
		})
	}
}
