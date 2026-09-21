package analyzer

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/terminal"
)

func captureReport(r Report) model.Capture {
	c := model.Capture{Manifest: r.Manifest, Host: r.Host}
	segment := model.Segment{StartMonoNS: r.Manifest.StartMonoNS, EndMonoNS: r.Manifest.EndMonoNS, Events: r.Timeline}
	for _, s := range r.Signals {
		segment.Metrics = append(segment.Metrics, model.Metric{Family: s.Family, StartMonoNS: r.Manifest.StartMonoNS, EndMonoNS: r.Manifest.StartMonoNS + s.CoveredNS, Count: s.Count, Anomalies: s.Anomalies, Histogram: s.Histogram, Retransmits: s.Retransmits, Resets: s.Resets, Loss: s.Loss, BookkeepingCompletions: s.BookkeepingCompletions})
	}
	c.Segments = []model.Segment{segment}
	return c
}

func TestJSONAndTerminalShareAssessment(t *testing.T) {
	r := quietReport()
	r.Signals[0].Loss.Unmatched = 54
	r.Manifest.Health.Sensors[0].Loss.Unmatched = 70
	r.Manifest.Settings.SchedulerThresholdNS = uint64(20 * time.Millisecond)
	r.Signals[1].Anomalies = 1
	r.Timeline = []model.Event{{MonoNS: 5, Type: "scheduler", Comm: "initd", PID: 272, LatencyNS: uint64(4850 * time.Millisecond)}}
	r = Analyze(captureReport(r))
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err = json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Assessment, r.Assessment) {
		t.Fatal("JSON changed the shared assessment")
	}
	if strings.Contains(string(data), "\u001b") {
		t.Fatal("JSON contains colors")
	}
	if r.Assessment.Code != "signals_to_review" || r.Assessment.SignalState != "review" || r.Assessment.EvidenceState != "limited" {
		t.Fatalf("incorrect verdict: %+v", r.Assessment)
	}
	if len(r.Assessment.Reasons) != 1 {
		t.Fatalf("unexpected reasons: %+v", r.Assessment.Reasons)
	}
	n := r.Assessment.Reasons[0]
	if n.Code != "unmatched_completions" || n.Scope != "window" || n.Sensor != "block_io" || n.Count != 54 || n.LifetimeCount == nil || *n.LifetimeCount != 70 || len(n.Evidence) == 0 {
		t.Fatalf("missing structured provenance: %+v", n)
	}
	if len(r.Assessment.Highlights) != 1 || r.Assessment.Highlights[0].EventIndex != 0 || r.Assessment.Highlights[0].ThresholdNS != uint64(20*time.Millisecond) {
		t.Fatal("exact outlier evidence missing")
	}
	var out bytes.Buffer
	if err = RenderWithOptions(&out, decoded, RenderOptions{Theme: terminal.Theme{Width: 100}}); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{r.Assessment.Title, "1 slow observation,", "54 untimed", "worst retained 4.85s", "Largest retained latency: Scheduler 4.85s", "1 slow runnable wait /", "percentiles cover measured observations only"} {
		if !strings.Contains(out.String(), text) {
			t.Fatalf("missing %q:\n%s", text, out.String())
		}
	}
	if tone, _, _ := signalView(r, r.Signals[0]); tone != terminal.Warning {
		t.Fatal("incomplete I/O evidence rendered green")
	}
}

func TestBookkeepingDoesNotDegradeCoverage(t *testing.T) {
	r := quietReport()
	r.Signals[0].BookkeepingCompletions = 32
	r.Manifest.Health.Sensors[0].BookkeepingCompletions = 64
	r = Analyze(captureReport(r))
	if r.Assessment.Code != "no_anomalies_observed" || r.Assessment.EvidenceState != "complete" || r.Signals[0].BookkeepingCompletions != 32 {
		t.Fatalf("normal kernel bookkeeping became loss: %+v", r.Assessment)
	}
	var out bytes.Buffer
	_ = RenderWithOptions(&out, r, RenderOptions{Verbose: true})
	if !strings.Contains(out.String(), "64 zero-byte logical WRITE completions") {
		t.Fatal("lifetime bookkeeping is not observable")
	}
}

func TestBoundaryEvidenceCountsPerSubsystemAndMissingDetails(t *testing.T) {
	r := quietReport()
	r.Signals[0].Anomalies = 4
	r.Timeline = []model.Event{{Type: "scheduler", LatencyNS: 100}, {Type: "scheduler", LatencyNS: 100}, {Type: "tcp_reset"}}
	a := assess(r)
	if a.Observed.Slow != 6 || a.Observed.Resets != 1 {
		t.Fatalf("subsystem evidence was undercounted or double counted: %+v", a.Observed)
	}
	found := false
	for _, reason := range a.Reasons {
		found = found || reason.Code == "anomaly_details_missing" && reason.Sensor == "block_io"
	}
	if !found {
		t.Fatal("unrelated retained events hid missing I/O attribution")
	}
}

func TestHistoryExplainsRecorderStartupOnlyWhenRecorded(t *testing.T) {
	r := quietReport()
	r.Manifest.StartMonoNS = uint64(10 * time.Second)
	r.Manifest.RequestedStartMonoNS = uint64(time.Second)
	r.Manifest.EndMonoNS = uint64(70 * time.Second)
	for _, recordedStart := range []uint64{0, uint64(10 * time.Second)} {
		r.Manifest.RecordingStartMonoNS = recordedStart
		a := assess(r)
		n := a.Reasons[len(a.Reasons)-1]
		if n.Code != "history_truncated" || !strings.Contains(n.Explanation, "9s of the requested 1m9s") {
			t.Fatalf("missing history is not quantified: %+v", n)
		}
		if strings.Contains(n.Explanation, "had not started") != (recordedStart != 0) {
			t.Fatal("startup reason inferred for an old capture")
		}
	}
}

func TestOutlierOutsideDisplayedTimelineRemainsVisible(t *testing.T) {
	r := quietReport()
	for i := 0; i < 120; i++ {
		r.Timeline = append(r.Timeline, model.Event{MonoNS: uint64(i + 1), Type: "scheduler", PID: 42, Comm: "worker", LatencyNS: uint64(25 * time.Millisecond)})
	}
	r.Timeline[119].LatencyNS = uint64(5 * time.Second)
	r.Signals[1].Anomalies = 120
	r = Analyze(captureReport(r))
	var normal, verbose bytes.Buffer
	_ = Render(&normal, r)
	_ = RenderWithOptions(&verbose, r, RenderOptions{Verbose: true})
	if !strings.Contains(normal.String(), "100 more events") || !strings.Contains(verbose.String(), "20 more events") {
		t.Fatal("event limits were not applied")
	}
	for _, out := range []string{normal.String(), verbose.String()} {
		if !strings.Contains(out, "Largest retained latency: Scheduler 5.00s") {
			t.Fatal("a severe late event was hidden by the display limit")
		}
	}
	if len(r.Timeline) != 120 || r.Assessment.Highlights[0].EventIndex != 119 {
		t.Fatal("presentation limits truncated JSON evidence")
	}
}

func TestNarrowReportAndLongEndpointsFitTerminal(t *testing.T) {
	r := quietReport()
	r.Timeline = []model.Event{{Type: "tcp_reset", SourceIP: "2001:db8:1234:5678:abcd:ef01:2345:6789", DestinationIP: "2001:db8:1234:5678:abcd:ef01:2345:6788", SourcePort: 65535, DestinationPort: 65534}}
	var out bytes.Buffer
	_ = RenderWithOptions(&out, r, RenderOptions{Theme: terminal.Theme{Width: 40}, Verbose: true})
	for _, line := range strings.Split(out.String(), "\n") {
		if utf8.RuneCountInString(line) > 40 {
			t.Fatalf("line overflows narrow terminal: %q", line)
		}
	}
	if !strings.Contains(out.String(), "Source") && !strings.Contains(out.String(), "Detail:") {
		t.Fatal("wide table lost labeled evidence")
	}
}

func TestLegacyTCPMissingMetadataIsExplicitAndNotAProcess(t *testing.T) {
	r := quietReport()
	r.Timeline = []model.Event{{Type: "tcp_reset"}, {Type: "tcp_reset"}, {Type: "tcp_reset"}}
	r = Analyze(captureReport(r))
	if len(r.Processes) != 0 {
		t.Fatalf("unattributed resets became a fake process: %+v", r.Processes)
	}
	if len(r.Assessment.Reasons) != 1 {
		t.Fatalf("missing endpoint evidence was not assessed: %+v", r.Assessment)
	}
	n := r.Assessment.Reasons[0]
	if n.Code != "tcp_endpoints_unavailable" || n.Count != 3 || n.Scope != "retained_events" || len(n.Evidence) != 3 {
		t.Fatalf("wrong metadata gap provenance: %+v", n)
	}
	var out bytes.Buffer
	_ = Render(&out, r)
	for _, text := range []string{"Endpoints unavailable", "process ownership is not collected", "Legacy reset direction was not recorded"} {
		if !strings.Contains(out.String(), text) {
			t.Fatalf("missing %q:\n%s", text, out.String())
		}
	}
	if strings.Contains(out.String(), ":0 → :0") || strings.Contains(out.String(), "unknown") {
		t.Fatal("unknown metadata was presented as a tuple or process")
	}
}

func TestSocketLessResetWithPacketTupleDoesNotLimitEvidence(t *testing.T) {
	r := quietReport()
	r.Timeline = []model.Event{{Type: "tcp_reset", SourceIP: "127.0.0.1", DestinationIP: "127.0.0.1", SourcePort: 49881, DestinationPort: 37677, TCPDirection: "sent", SocketContext: "none", EndpointSource: "packet_header"}, {Type: "tcp_reset", SourceIP: "127.0.0.1", DestinationIP: "127.0.0.1", SourcePort: 49881, DestinationPort: 37677, TCPDirection: "received", SocketContext: "socket", EndpointSource: "socket"}}
	r = Analyze(captureReport(r))
	if r.Assessment.Code != "signals_to_review" || r.Assessment.EvidenceState != "complete" || len(r.Processes) != 0 {
		t.Fatalf("socket-less packet metadata became collection failure: %+v", r.Assessment)
	}
	var out bytes.Buffer
	_ = RenderWithOptions(&out, r, RenderOptions{Theme: terminal.Theme{Width: 100}, Verbose: true})
	for _, text := range []string{"TCP reset sent", "TCP reset received", "127.0.0.1:49881 →", "no associated socket", "packet header", "same reset at both ends"} {
		if !strings.Contains(out.String(), text) {
			t.Fatalf("missing %q:\n%s", text, out.String())
		}
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err = json.Unmarshal(data, &decoded); err != nil || !reflect.DeepEqual(decoded.Timeline, r.Timeline) {
		t.Fatal("TCP provenance or direction lost in JSON")
	}
}
