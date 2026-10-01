package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/terminal"
)

func renderStatus(w io.Writer, h model.Health, settings *model.RecordingSettings, t terminal.Theme, verbose bool) error {
	var b strings.Builder
	enabled, active := sensorCounts(h)
	notes := h.AutoCapture != nil && h.AutoCapture.LastError != ""
	for _, s := range h.Sensors {
		notes = notes || s.Loss != (model.Counters{})
	}
	notes = notes || h.IngressDrops+h.RecorderDrops+h.MetadataFailures+h.SnapshotFailures+h.ClockChanges > 0
	tone, title := terminal.Good, "RECORDER ACTIVE"
	if active < enabled || notes {
		tone, title = terminal.Warning, "RECORDER ACTIVE · COLLECTION NOTES"
	}
	if active == 0 {
		tone, title = terminal.Critical, "NO ACTIVE SENSORS"
	}
	if enabled == 0 {
		tone, title = terminal.Info, "RECORDER STATUS UNKNOWN"
	}
	lines := []string{fmt.Sprintf("%d / %d enabled sensors recording · %.2f / %.2f MiB history retained", active, enabled, float64(h.RetainedBytes)/(1<<20), float64(h.MaxBytes)/(1<<20))}
	if h.RetainedSpanNS != 0 {
		retained := "Oldest retained segment: " + time.Duration(h.RetainedSpanNS).Round(time.Second).String() + " ago"
		if settings != nil && settings.HistoryNS > 0 {
			retained += " · history target " + config.DurationText(time.Duration(settings.HistoryNS))
		}
		lines = append(lines, retained)
	}
	lines = append(lines, "Counters cover this daemon run. Analyze a snapshot to assess workload signals.")
	t.Panel(&b, tone, title, lines...)
	t.Section(&b, "SENSORS")
	for _, s := range h.Sensors {
		tone, state := terminal.Good, "Recording"
		if s.State == "disabled" {
			tone, state = terminal.Muted, "Disabled by configuration"
		} else if s.State != "healthy" {
			tone, state = terminal.Warning, "Coverage "+s.State
		}
		detail := ""
		if s.KernelBytesKnown {
			detail = fmt.Sprintf("BPF allocation %.2f MiB", float64(s.KernelBytes)/(1<<20))
		}
		if s.Reason != "" {
			detail = s.Reason
		}
		t.Notice(&b, tone, terminal.Sensor(s.Name)+" — "+state)
		if detail != "" {
			t.Line(&b, terminal.Muted, "    ", detail)
		}
	}
	if a := h.AutoCapture; a != nil {
		t.Section(&b, "AUTOMATIC CAPTURES")
		tone := terminal.Info
		if a.LastError != "" || a.State == "inactive" {
			tone = terminal.Warning
		}
		t.Notice(&b, tone, "State: "+a.State, "Sources: "+strings.Join(a.Sensors, ", ")+" · "+a.Directory)
		t.Line(&b, terminal.Muted, "    ", fmt.Sprintf("Detected %d · saved %d · coalesced %d · failures %d (daemon lifetime)", a.Detected, a.Saved, a.Coalesced, a.Failures))
		if a.PendingUntilNS != 0 {
			pending := "Window complete; waiting for snapshot writer"
			if a.PendingForNS > 0 {
				pending = "Window ends in " + time.Duration(a.PendingForNS).Round(time.Second).String()
			}
			t.Line(&b, terminal.Muted, "    ", pending)
		}
		if a.LastPath != "" {
			t.Line(&b, terminal.Muted, "    ", "Last: "+a.LastPath+" · "+a.LastSavedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
		}
		if a.LastError != "" {
			t.Line(&b, terminal.Warning, "    ", "Last failure: "+a.LastError)
		}
	}
	if h.ClockChanges > 0 {
		t.Section(&b, "CLOCK")
		label := "wall-clock discontinuities"
		if h.ClockChanges == 1 {
			label = "wall-clock discontinuity"
		}
		t.Notice(&b, terminal.Warning, fmt.Sprintf("%d %s detected", h.ClockChanges, label), "Recording continued. Capture UTC timestamps use a current clock sample; older timestamps may be shifted.")
		if step := h.LastClockChange; step != nil {
			t.Line(&b, terminal.Muted, "    ", fmt.Sprintf("Last detected %s UTC · offset change %s", step.DetectedAt.UTC().Format("2006-01-02 15:04:05"), time.Duration(step.OffsetChangeNS)))
		}
		if h.ObservedAt != nil {
			t.Line(&b, terminal.Muted, "    ", "Current UTC (realtime): "+h.ObservedAt.UTC().Format("2006-01-02 15:04:05"))
		}
	}
	if notes {
		t.Section(&b, "COLLECTION NOTES · SINCE DAEMON START")
		for _, s := range h.Sensors {
			for _, n := range model.CounterNotes(s.Name, s.Loss) {
				t.Notice(&b, terminal.Warning, terminal.Sensor(s.Name)+": "+n.Title, n.Explanation)
				fmt.Fprintln(&b)
			}
		}
		if h.IngressDrops+h.RecorderDrops > 0 {
			t.Notice(&b, terminal.Warning, "Some observations were dropped", fmt.Sprintf("%s event details could not enter userspace ingress; %s observations could not be retained by the recorder. Individual events or metric intervals may be missing.", terminal.Count(h.IngressDrops), terminal.Count(h.RecorderDrops)))
		}
		if h.MetadataFailures > 0 {
			t.Notice(&b, terminal.Info, terminal.Count(h.MetadataFailures)+" process identities could not be resolved", "Kernel observations were retained, but some process context is unavailable.")
		}
		if h.SnapshotFailures > 0 {
			t.Notice(&b, terminal.Warning, terminal.Count(h.SnapshotFailures)+" snapshot writes failed", "Some requested captures could not be saved. Recording may still be active.")
		}
	}
	if verbose {
		t.Section(&b, "DIAGNOSTICS · SINCE DAEMON START")
		rows := []string{}
		for _, s := range h.Sensors {
			rows = append(rows, fmt.Sprintf("%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d", terminal.Sensor(s.Name), s.State, s.Loss.RingFailures, s.Loss.Suppressed, s.Loss.DetailFailures, s.Loss.TrackingFailures, s.Loss.Unmatched, s.Loss.DecodeFailures))
		}
		t.Table(&b, "Sensor\tState\tBuffer rejected\tRate limited\tQuota failed\tStart unsaved\tStart missing\tDetail invalid", rows, nil)
		for _, s := range h.Sensors {
			if s.BookkeepingCompletions > 0 {
				t.Line(&b, terminal.Muted, "  ", fmt.Sprintf("%s: %s zero-byte logical WRITE completions excluded as bookkeeping; dispatched cache flushes are still measured.", terminal.Sensor(s.Name), terminal.Count(s.BookkeepingCompletions)))
			}
		}
		t.Table(&b, "Recorder counter\tLifetime total", []string{fmt.Sprintf("Ingress detail drops\t%d", h.IngressDrops), fmt.Sprintf("Recorder observation drops\t%d", h.RecorderDrops), fmt.Sprintf("Memory history evictions\t%d", h.EvictedSegments), fmt.Sprintf("Unresolved process identities\t%d", h.MetadataFailures), fmt.Sprintf("Snapshot write failures\t%d", h.SnapshotFailures)}, nil)
	}
	fmt.Fprintln(&b)
	if !verbose {
		t.Line(&b, terminal.Muted, "  ", "--verbose: lifetime counters · --json: machine-readable health")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func sensorCounts(h model.Health) (enabled, active int) {
	for _, sensor := range h.Sensors {
		if sensor.State != "disabled" {
			enabled++
		}
		if sensor.State == "healthy" {
			active++
		}
	}
	return enabled, active
}
