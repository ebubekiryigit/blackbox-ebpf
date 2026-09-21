package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/terminal"
)

func renderStatus(w io.Writer, h model.Health, t terminal.Theme, verbose bool) error {
	var b strings.Builder
	enabled, active := sensorCounts(h)
	notes := false
	for _, s := range h.Sensors {
		notes = notes || s.Loss != (model.Counters{})
	}
	notes = notes || h.IngressDrops+h.RecorderDrops+h.MetadataFailures+h.SnapshotFailures > 0
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
	t.Panel(&b, tone, title, fmt.Sprintf("%d / %d enabled sensors recording · %.2f / %.2f MiB history retained", active, enabled, float64(h.RetainedBytes)/(1<<20), float64(h.MaxBytes)/(1<<20)), "Counters cover this daemon run. Analyze a snapshot to assess workload signals.")
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
			rows = append(rows, fmt.Sprintf("%s\t%s\t%d\t%d\t%d\t%d\t%d", terminal.Sensor(s.Name), s.State, s.Loss.RingFailures, s.Loss.Suppressed, s.Loss.TrackingFailures, s.Loss.Unmatched, s.Loss.DecodeFailures))
		}
		t.Table(&b, "Sensor\tState\tBuffer rejected\tRate limited\tStart unsaved\tStart missing\tDetail invalid", rows, nil)
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
