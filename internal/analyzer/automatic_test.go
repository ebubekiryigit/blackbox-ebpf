package analyzer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestAutomaticReasonsDoNotDoubleCountRetainedEvidence(t *testing.T) {
	c := model.Capture{Manifest: model.Manifest{StartMonoNS: 10, RequestedStartMonoNS: 10, EndMonoNS: 30, AutoIncident: &model.AutoIncident{DetectedMonoNS: 20, EndMonoNS: 30, BeforeNS: 10, AfterNS: 10, Triggers: []model.AutoTrigger{{Family: "oom", Reason: "oom_victim", Count: 2, FirstIntervalStartNS: 10, LastIntervalEndNS: 20}}}, Health: model.Health{Sensors: []model.SensorHealth{{Name: "oom", State: "healthy"}}}}, Segments: []model.Segment{{Metrics: []model.Metric{{Family: "oom", StartMonoNS: 10, EndMonoNS: 20, Count: 2}}}}}
	r := Analyze(c)
	if r.Assessment.Observed.OOMVictims != 2 || r.Assessment.Code != "oom_victims_observed" {
		t.Fatal("trigger double counted", r.Assessment)
	}
	var b bytes.Buffer
	if err := Render(&b, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "AUTOMATIC CAPTURE") || !strings.Contains(b.String(), "polled aggregates") {
		t.Fatal("missing trigger context", b.String())
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"kind":"auto_trigger"`)) {
		t.Fatal("missing machine-readable evidence reference")
	}
	c.Segments = nil
	c.Manifest.StartMonoNS = 25
	r = Analyze(c)
	if r.Assessment.Code != "critical_trigger_detected" || r.Assessment.Severity != "critical" || r.Assessment.EvidenceState != "unavailable" || r.Assessment.Observed.OOMVictims != 0 {
		t.Fatal("missing trigger intervals silently turned green", r.Assessment)
	}
	b.Reset()
	if err := Render(&b, r); err != nil || !strings.Contains(b.String(), "CRITICAL TRIGGER DETECTED · EVIDENCE LIMITED") {
		t.Fatal("missing trigger verdict", err, b.String())
	}
	found := false
	for _, reason := range r.Assessment.Reasons {
		found = found || reason.Code == "trigger_intervals_missing"
	}
	if !found {
		t.Fatal("missing trigger coverage not explained")
	}
	c.Manifest.AutoIncident = nil
	r = Analyze(c)
	b.Reset()
	Render(&b, r)
	if strings.Contains(b.String(), "AUTOMATIC CAPTURE") {
		t.Fatal("invented automatic metadata for old capture")
	}
}

func TestAutomaticTriggerWithoutRetainedCriticalAggregate(t *testing.T) {
	c := model.Capture{Manifest: model.Manifest{StartMonoNS: 10, RequestedStartMonoNS: 10, EndMonoNS: 30, AutoIncident: &model.AutoIncident{DetectedMonoNS: 20, EndMonoNS: 30, BeforeNS: 10, AfterNS: 10, Triggers: []model.AutoTrigger{{Family: "scheduler", Reason: "critical_latency", Count: 1, ThresholdNS: 100, FirstIntervalStartNS: 10, LastIntervalEndNS: 20}}}, Health: model.Health{Sensors: []model.SensorHealth{{Name: "scheduler", State: "healthy"}}}}, Segments: []model.Segment{{Metrics: []model.Metric{{Family: "scheduler", StartMonoNS: 20, EndMonoNS: 30, Count: 10}}}}}
	r := Analyze(c)
	if a := r.Assessment; a.Code != "critical_trigger_detected" || a.Observed.Critical != 0 || a.EvidenceState != "limited" {
		t.Fatal("trigger evidence classified as retained aggregate", r.Assessment)
	}
	found := false
	for _, reason := range r.Assessment.Reasons {
		found = found || reason.Code == "trigger_evidence_not_retained"
	}
	if !found {
		t.Fatal("lost trigger aggregate has no coverage reason", r.Assessment)
	}
	c.Segments[0].Metrics[0].Critical = 1
	r = Analyze(c)
	if a := r.Assessment; a.Code != "critical_latency_observed" || a.Observed.Critical != 1 {
		t.Fatal("retained critical aggregate lost its verdict", a)
	}
}
