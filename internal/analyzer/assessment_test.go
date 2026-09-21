package analyzer

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/terminal"
)

func quietReport() Report {
	r := Report{Manifest: model.Manifest{StartMonoNS: 1, RequestedStartMonoNS: 1, EndMonoNS: 1 + uint64(time.Minute)}}
	for _, family := range model.Families {
		r.Signals = append(r.Signals, Summary{Family: family, State: "healthy", Available: true, CoveredNS: uint64(time.Minute)})
		r.Manifest.Health.Sensors = append(r.Manifest.Health.Sensors, model.SensorHealth{Name: family, State: "healthy"})
	}
	r.Signals[0].Count = 59
	r.Signals[1].Count = 20456
	return r
}

func TestAssessmentSeparatesSignalsAndEvidence(t *testing.T) {
	cases := []struct {
		name            string
		change          func(*Report)
		tone            terminal.Tone
		title, evidence string
	}{
		{"quiet", func(*Report) {}, terminal.Good, "NO ANOMALIES OBSERVED", "no collection gaps"},
		{"missing I/O starts", func(r *Report) { r.Signals[0].Loss.Unmatched = 11 }, terminal.Warning, "EVIDENCE LIMITED", "incomplete"},
		{"invalid detail", func(r *Report) { r.Signals[1].Loss.DecodeFailures = 2 }, terminal.Warning, "EVIDENCE LIMITED", "incomplete"},
		{"historical loss only", func(r *Report) { r.Manifest.Health.Sensors[0].Loss.Unmatched = 48 }, terminal.Good, "NO ANOMALIES OBSERVED", "no collection gaps"},
		{"slow I/O", func(r *Report) { r.Signals[0].Anomalies = 1 }, terminal.Warning, "SIGNALS TO REVIEW", "incomplete"},
		{"OOM aggregate without detail", func(r *Report) { r.Signals[3].Count = 1 }, terminal.Critical, "OOM VICTIMS", "incomplete"},
		{"OOM detail without aggregate", func(r *Report) { r.Timeline = []model.Event{{Type: "oom"}} }, terminal.Critical, "OOM VICTIMS", "no collection gaps"},
		{"TCP detail without aggregate", func(r *Report) {
			r.Timeline = []model.Event{{Type: "tcp_reset", SourceIP: "127.0.0.1", DestinationIP: "127.0.0.1"}}
		}, terminal.Warning, "SIGNALS TO REVIEW", "no collection gaps"},
		{"sensor failed", func(r *Report) { r.Signals[2].State = "error"; r.Signals[2].Reason = "reader failed" }, terminal.Warning, "EVIDENCE LIMITED", "incomplete"},
		{"intentional disable", func(r *Report) { r.Signals[2].State = "disabled" }, terminal.Good, "NO ANOMALIES OBSERVED", "no collection gaps"},
		{"missing metrics", func(r *Report) { r.Signals[0].CoveredNS = 0 }, terminal.Warning, "EVIDENCE LIMITED", "incomplete"},
		{"boundary intervals", func(r *Report) { r.Signals[0].CoveredNS -= uint64(time.Second) }, terminal.Good, "NO ANOMALIES OBSERVED", "no collection gaps"},
		{"large metric gap", func(r *Report) { r.Signals[0].CoveredNS = uint64(5 * time.Second) }, terminal.Warning, "EVIDENCE LIMITED", "incomplete"},
		{"no metrics at all", func(r *Report) {
			for i := range r.Signals {
				r.Signals[i].Count = 0
				r.Signals[i].CoveredNS = 0
			}
		}, terminal.Warning, "INSUFFICIENT EVIDENCE", "incomplete"},
		{"no activity", func(r *Report) { r.Signals[0].Count = 0; r.Signals[1].Count = 0 }, terminal.Info, "NO ACTIVITY TO ASSESS", "no collection gaps"},
		{"unlocated recorder loss", func(r *Report) { r.Manifest.Health.RecorderDrops = 1 }, terminal.Warning, "EVIDENCE LIMITED", "incomplete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := quietReport()
			tc.change(&r)
			got := assess(r)
			if assessmentTone(got) != tc.tone || !strings.Contains(got.Title, tc.title) || !strings.Contains(got.Evidence, tc.evidence) {
				t.Fatalf("incorrect assessment: %+v", got)
			}
		})
	}
}

func TestReportExplainsInvalidDetailsWithoutDiscardingAggregates(t *testing.T) {
	r := quietReport()
	r.Signals[1].Loss.DecodeFailures = 2
	r.Manifest.Health.Sensors[1].Loss.DecodeFailures = 3
	var out bytes.Buffer
	if err := RenderWithOptions(&out, r, RenderOptions{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"2 event details could not be decoded", "Aggregate counts", "histograms remain available", "Detail invalid", "3"} {
		if !strings.Contains(out.String(), expected) {
			t.Fatalf("missing decode-loss explanation %q:\n%s", expected, out.String())
		}
	}
}

func TestReportExplainsMissingStartsAndScope(t *testing.T) {
	r := quietReport()
	r.Signals[0].Loss.Unmatched = 11
	r.Manifest.Health.Sensors[0].Loss.Unmatched = 48
	var plain, colored bytes.Buffer
	if err := Render(&plain, r); err != nil {
		t.Fatal(err)
	}
	if err := RenderWithOptions(&colored, r, RenderOptions{Theme: terminal.Theme{Color: true}}); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"NO ANOMALIES OBSERVED", "EVIDENCE LIMITED", "11 I/O completions could not be timed", "excluded from the I/O histogram", "this window", "48 since daemon start"} {
		if !strings.Contains(plain.String(), expected) {
			t.Fatalf("missing explanation %q:\n%s", expected, plain.String())
		}
	}
	if strings.Contains(plain.String(), "\x1b[") || !strings.Contains(colored.String(), "\x1b[") {
		t.Fatal("incorrect plain/color separation")
	}
	if strings.Contains(plain.String(), "DIAGNOSTICS") || strings.Contains(plain.String(), "No process identities retained") {
		t.Fatal("empty diagnostic sections clutter the default report")
	}
}

func TestDirectEventsCannotProduceClearSubsystemCard(t *testing.T) {
	r := quietReport()
	r.Timeline = []model.Event{{Type: "block_io", LatencyNS: uint64(200 * time.Millisecond)}, {Type: "tcp_reset"}}
	for _, index := range []int{0, 2} {
		tone, headline, _ := signalView(r, r.Signals[index])
		if tone != terminal.Warning || !strings.Contains(headline, "retained") {
			t.Fatalf("direct evidence hidden by aggregate totals: %s", headline)
		}
	}
}

func TestCoverageUsesRecordedPollIntervalAndLegacyFallback(t *testing.T) {
	r := quietReport()
	r.Signals[0].CoveredNS -= uint64(3 * time.Second)
	if assess(r).EvidenceState == "complete" {
		t.Fatal("legacy gap hidden")
	}
	r.Manifest.Settings.PollIntervalNS = uint64(2 * time.Second)
	if len(assess(r).Reasons) != 0 {
		t.Fatal("configured boundary intervals were reported as missing evidence")
	}
	r.Signals[0].CoveredNS -= uint64(5 * time.Second)
	if len(assess(r).Reasons) == 0 {
		t.Fatal("real gap hidden by configurable interval")
	}
}
