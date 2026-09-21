package analyzer

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/terminal"
)

type RenderOptions struct {
	Theme        terminal.Theme
	Verbose      bool
	EventLimit   int
	ProcessLimit int
}

// Render produces a readable plain report for callers that do not select a theme.
func Render(w io.Writer, r Report) error { return RenderWithOptions(w, r, RenderOptions{}) }

func RenderWithOptions(w io.Writer, r Report, options RenderOptions) error {
	var b strings.Builder
	t := options.Theme
	a := r.Assessment
	if a.Code == "" {
		a = assess(r)
	}
	lines := []string{a.Signals, a.Evidence}
	if len(a.Highlights) > 0 {
		worst := a.Highlights[0]
		for _, h := range a.Highlights[1:] {
			if h.LatencyNS > worst.LatencyNS {
				worst = h
			}
		}
		e := r.Timeline[worst.EventIndex]
		lines = append(lines, fmt.Sprintf("Largest retained latency: %s %s · %s PID %d.", terminal.Sensor(worst.Family), latency(worst.LatencyNS), name(e.Comm), e.PID))
	}
	t.Panel(&b, assessmentTone(a), a.Title, lines...)
	start, end := r.Host.Wall(r.Manifest.StartMonoNS).UTC(), r.Host.Wall(r.Manifest.EndMonoNS).UTC()
	t.Line(&b, terminal.Muted, "  ", fmt.Sprintf("%s · Linux %s · %s · %s · Blackbox %s", terminal.Clean(r.Host.Hostname), terminal.Clean(r.Host.Kernel), terminal.Clean(r.Host.Architecture), terminal.Clean(r.Manifest.Mode), terminal.Clean(r.Manifest.ApplicationVersion)))
	t.Line(&b, terminal.Muted, "  ", fmt.Sprintf("%s → %s UTC · %s", start.Format("2006-01-02 15:04:05.000"), end.Format("2006-01-02 15:04:05.000"), end.Sub(start).Round(time.Millisecond)))
	if r.Manifest.Mode == "synthetic-demo" {
		t.Notice(&b, terminal.Info, "Synthetic demonstration", "These observations were generated; no host was recorded.")
	}

	t.Section(&b, "SIGNALS")
	for _, s := range r.Signals {
		tone, headline, detail := signalView(r, s)
		t.Notice(&b, tone, terminal.Sensor(s.Family)+" — "+headline, detail)
	}
	t.Line(&b, terminal.Muted, "  ", "Latency percentiles are histogram bounds. Conclusions apply to captured evidence.")

	if len(a.Reasons) > 0 {
		t.Section(&b, "EVIDENCE TO REVIEW")
		for i, n := range a.Reasons {
			if i > 0 {
				fmt.Fprintln(&b)
			}
			t.Notice(&b, severityTone(n.Severity), n.Title, n.Explanation)
			t.Line(&b, terminal.Muted, "    ", reasonContext(n))
		}
	}
	if len(r.Timeline) > 0 {
		t.Section(&b, "EVENTS · UTC")
		limit := options.EventLimit
		if limit <= 0 {
			limit = config.Default().Report.Events
			if options.Verbose {
				limit = config.Default().Report.VerboseEvents
			}
		}
		rows, tones := make([]string, 0, min(limit, len(r.Timeline))), make([]terminal.Tone, 0, min(limit, len(r.Timeline)))
		block, tcp, legacyReset := false, false, false
		for _, e := range r.Timeline[:min(limit, len(r.Timeline))] {
			detail, tone := "", terminal.Warning
			signal, process := eventName(e.Type), name(e.Comm)
			switch e.Type {
			case "scheduler":
				detail = fmt.Sprintf("CPU %d", e.CPU)
				if threshold := criticalThreshold(r.Manifest.Settings, e.Type); threshold > 0 && e.LatencyNS >= threshold {
					tone = terminal.Critical
				}
			case "block_io":
				block = true
				detail = fmt.Sprintf("%s %d:%d · %d B", terminal.Clean(e.Operation), e.Major, e.Minor, e.Bytes)
				if threshold := criticalThreshold(r.Manifest.Settings, e.Type); threshold > 0 && e.LatencyNS >= threshold {
					tone = terminal.Critical
				}
			case "oom":
				detail, tone = "OOM victim", terminal.Critical
			case "tcp_retransmit", "tcp_reset":
				tcp = true
				if e.Comm == "" && e.PID == 0 {
					process = "—"
				}
				separator := " → "
				if e.Type == "tcp_reset" {
					switch e.TCPDirection {
					case "sent":
						signal = "TCP reset sent"
					case "received":
						signal = "TCP reset received"
					default:
						separator, legacyReset = " ↔ ", true
					}
				}
				if e.SourceIP == "" && e.DestinationIP == "" {
					detail = "Endpoints unavailable"
				} else {
					detail = tcpEndpoint(e.SourceIP, e.SourcePort) + separator + tcpEndpoint(e.DestinationIP, e.DestinationPort)
				}
				if e.SocketContext == "none" {
					detail += " · no associated socket"
				}
				if options.Verbose && e.EndpointSource == "packet_header" {
					detail += " · packet header"
				}
			}
			pid := "—"
			if e.PID != 0 {
				pid = strconv.FormatUint(uint64(e.PID), 10)
			}
			rows = append(rows, fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s", r.Host.Wall(e.MonoNS).UTC().Format("15:04:05.000"), process, pid, signal, latency(e.LatencyNS), detail))
			tones = append(tones, tone)
		}
		t.Table(&b, "Time\tProcess\tPID\tSignal\tLatency\tDetail", rows, tones)
		if len(r.Timeline) > limit {
			t.Line(&b, terminal.Muted, "  ", fmt.Sprintf("%s more events. Text event limit reached; adjust report limits or use --json for all.", terminal.Count(uint64(len(r.Timeline)-limit))))
		}
		if block {
			t.Line(&b, terminal.Muted, "  ", "I/O process names identify dispatch context, which may be a kernel worker.")
		}
		if tcp {
			t.Line(&b, terminal.Muted, "  ", "TCP process ownership is not collected. Sent/received counts are kernel observations; loopback can observe the same reset at both ends.")
			if legacyReset {
				t.Line(&b, terminal.Muted, "  ", "Legacy reset direction was not recorded; endpoint pairs (↔) are shown as saved.")
			}
		}
		processes(&b, r, options)
	} else {
		fmt.Fprintln(&b)
		t.Line(&b, terminal.Muted, "  ", "No individual event details retained. Normal activity is summarized above.")
	}
	for _, f := range r.Findings {
		if f.Category == "correlation" {
			fmt.Fprintln(&b)
			t.Notice(&b, terminal.Info, "Signals coincided for the same process or cgroup", "Retained events occurred within one second. This timing does not establish a cause.")
		}
	}
	if options.Verbose {
		diagnostics(&b, r, t)
	}
	fmt.Fprintln(&b)
	if !options.Verbose {
		t.Line(&b, terminal.Muted, "  ", "--verbose: lifetime counters and diagnostics · --json: complete evidence")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func signalView(r Report, s Summary) (terminal.Tone, string, string) {
	var retained uint64
	var worst uint64
	var worstProcess string
	var worstPID uint32
	for _, e := range r.Timeline {
		if s.Family == "oom" && e.Type == "oom" || s.Family == "tcp" && (e.Type == "tcp_reset" || e.Type == "tcp_retransmit") || s.Family == e.Type && e.LatencyNS > 0 {
			retained++
			if e.LatencyNS > worst {
				worst, worstProcess, worstPID = e.LatencyNS, name(e.Comm), e.PID
			}
		}
	}
	if s.State == "disabled" {
		return terminal.Muted, "Disabled", "Excluded by recording configuration."
	}
	if s.State != "healthy" {
		detail := "Sensor " + s.State + ". " + s.Reason
		if s.CoveredNS > 0 {
			detail += fmt.Sprintf(" Earlier metrics: %.1fs.", float64(s.CoveredNS)/1e9)
		}
		return terminal.Warning, "Coverage unavailable or incomplete", detail
	}
	coverage := fmt.Sprintf("%.1fs monitored", float64(s.CoveredNS)/1e9)
	if s.CoveredNS == 0 {
		if retained > 0 {
			tone := terminal.Warning
			if s.Family == "oom" || criticalCount(r, s) > 0 {
				tone = terminal.Critical
			}
			return tone, terminal.Count(retained) + " retained events to review", "Direct event evidence available; no full aggregate interval retained."
		}
		return terminal.Info, "No complete metrics to assess", "No full aggregate interval retained."
	}
	switch s.Family {
	case "block_io", "scheduler":
		unit, singular, empty := "I/O requests", "I/O request", "No completed I/O requests measured"
		threshold := r.Manifest.Settings.BlockThresholdNS
		if s.Family == "scheduler" {
			unit, singular, empty, threshold = "runnable waits", "runnable wait", "No runnable waits measured", r.Manifest.Settings.SchedulerThresholdNS
		}
		if s.Anomalies == 0 && retained > 0 {
			tone := terminal.Warning
			if criticalCount(r, s) > 0 {
				tone = terminal.Critical
			}
			return tone, quantity(retained, "retained slow "+singular, "retained slow "+unit), coverage + " · " + terminal.Count(s.Count) + " aggregate measurements; individual slow events appear below"
		}
		if s.Count == 0 {
			if s.Loss.Unmatched > 0 {
				return terminal.Warning, terminal.Count(s.Loss.Unmatched) + " untimed completions / no measured latency", coverage + " · no matching start records; latency cannot be assessed"
			}
			return terminal.Info, empty, coverage + " · latency unavailable"
		}
		tone, headline := terminal.Good, "No slow "+unit
		if s.Anomalies > 0 {
			tone, headline = terminal.Warning, quantity(s.Anomalies, "slow "+singular, "slow "+unit)
		}
		headline += " / " + terminal.Count(s.Count) + " measured"
		if s.Loss.Unmatched > 0 {
			tone = terminal.Warning
			headline += " · " + terminal.Count(s.Loss.Unmatched) + " untimed"
		}
		if s.Loss.TrackingFailures > 0 {
			tone = terminal.Warning
		}
		if threshold > 0 {
			headline += " (≥" + latency(threshold) + ")"
		}
		detail := fmt.Sprintf("p50 %s · p95 %s · p99 %s · %s", percentile(s.Histogram, 50), percentile(s.Histogram, 95), percentile(s.Histogram, 99), coverage)
		if s.Loss.Unmatched > 0 {
			detail += " · percentiles cover measured observations only"
		}
		if worst > 0 {
			detail += fmt.Sprintf(" · worst retained %s (%s, PID %d)", latency(worst), worstProcess, worstPID)
		}
		if critical := criticalCount(r, s); critical > 0 {
			tone = terminal.Critical
			detail += fmt.Sprintf(" · %s critical (≥%s)", terminal.Count(critical), latency(criticalThreshold(r.Manifest.Settings, s.Family)))
		}
		return tone, headline, detail
	case "tcp":
		if s.Retransmits+s.Resets > 0 {
			resetUnit := "reset observations"
			if s.Resets == 1 {
				resetUnit = "reset observation"
			}
			return terminal.Warning, fmt.Sprintf("%s retransmits · %s %s", terminal.Count(s.Retransmits), terminal.Count(s.Resets), resetUnit), coverage + " · connection events to review; resets can be expected"
		}
		if retained > 0 {
			return terminal.Warning, terminal.Count(retained) + " retained TCP events", coverage + " · individual connection events appear below"
		}
		return terminal.Good, "No retransmissions or resets observed", coverage
	case "oom":
		n := s.Count
		n = max(n, retained)
		if n > 0 {
			return terminal.Critical, terminal.Count(n) + " OOM victim events", coverage + " · the kernel selected processes as out-of-memory victims"
		}
		return terminal.Good, "No OOM victims observed", coverage
	}
	return terminal.Info, "No interpretation available", coverage
}
func processes(w io.Writer, r Report, options RenderOptions) {
	rows := []string{}
	limit := options.ProcessLimit
	if limit <= 0 {
		limit = config.Default().Report.Processes
		if options.Verbose {
			limit = config.Default().Report.VerboseProcesses
		}
	}
	for _, p := range r.Processes {
		if p.TGID == 0 {
			continue
		}
		rows = append(rows, fmt.Sprintf("%s\t%d\t%s", name(p.Comm), p.TGID, terminal.Count(uint64(p.Details))))
		if len(rows) == limit {
			break
		}
	}
	if len(rows) == 0 {
		return
	}
	options.Theme.Section(w, "AFFECTED PROCESSES · RETAINED EVENTS")
	options.Theme.Table(w, "Process\tTGID\tEvents", rows, nil)
}
func diagnostics(w io.Writer, r Report, t terminal.Theme) {
	t.Section(w, "DIAGNOSTICS · SINCE DAEMON START")
	rows := make([]string, 0, len(r.Manifest.Health.Sensors))
	for _, s := range r.Manifest.Health.Sensors {
		rows = append(rows, fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s", terminal.Sensor(s.Name), s.State, terminal.Count(s.Loss.RingFailures), terminal.Count(s.Loss.Suppressed), terminal.Count(s.Loss.TrackingFailures), terminal.Count(s.Loss.Unmatched), terminal.Count(s.Loss.DecodeFailures)))
	}
	t.Table(w, "Sensor\tState\tBuffer rejected\tRate limited\tStart unsaved\tStart missing\tDetail invalid", rows, nil)
	t.Line(w, terminal.Muted, "  ", "These totals include activity outside this window; they are not additional window losses.")
	for _, s := range r.Manifest.Health.Sensors {
		for _, n := range model.CounterNotes(s.Name, s.Loss) {
			t.Line(w, terminal.Muted, "  ", terminal.Sensor(s.Name)+": "+n.Title+". "+n.Explanation)
		}
		if s.BookkeepingCompletions > 0 {
			t.Line(w, terminal.Muted, "  ", fmt.Sprintf("%s: %s zero-byte logical WRITE completions excluded from device I/O counts. Flush-sequence bookkeeping is not missing latency evidence; dispatched cache flushes are still measured.", terminal.Sensor(s.Name), terminal.Count(s.BookkeepingCompletions)))
		}
	}
	h := r.Manifest.Health
	t.Table(w, "Recorder counter\tLifetime total", []string{
		fmt.Sprintf("Ingress detail drops\t%d", h.IngressDrops), fmt.Sprintf("Recorder observation drops\t%d", h.RecorderDrops), fmt.Sprintf("Memory history evictions\t%d", h.EvictedSegments), fmt.Sprintf("Unresolved process identities\t%d", h.MetadataFailures), fmt.Sprintf("Snapshot write failures\t%d", h.SnapshotFailures),
	}, nil)
	if h.MetadataFailures > 0 {
		t.Line(w, terminal.Muted, "  ", "Unresolved process metadata does not discard the kernel observation.")
	}
}

func severityTone(s string) terminal.Tone {
	switch s {
	case "critical":
		return terminal.Critical
	case "warning":
		return terminal.Warning
	default:
		return terminal.Info
	}
}
func assessmentTone(a Assessment) terminal.Tone {
	if a.Code == "no_anomalies_observed" {
		return terminal.Good
	}
	return severityTone(a.Severity)
}
func reasonContext(n CoverageReason) string {
	context := ""
	if n.Sensor != "" {
		context = terminal.Sensor(n.Sensor) + " · "
	}
	switch n.Scope {
	case "window":
		context += "this window"
	case "requested_window":
		context += "requested window"
	case "retained_events":
		context += "retained details in this window"
	case "lifetime_window_unknown":
		context += "since daemon start; window impact unknown"
	default:
		context += "since daemon start"
	}
	if n.LifetimeCount != nil {
		context += " · " + terminal.Count(*n.LifetimeCount) + " since daemon start"
	}
	return context
}

func tcpEndpoint(ip string, port uint16) string {
	if ip == "" {
		return "unavailable"
	}
	return net.JoinHostPort(terminal.Clean(ip), strconv.Itoa(int(port)))
}
func name(s string) string {
	if s == "" {
		return "unknown"
	}
	return terminal.Clean(s)
}
func eventName(s string) string {
	switch s {
	case "block_io":
		return "I/O"
	case "scheduler":
		return "Scheduler"
	case "tcp_reset":
		return "TCP reset"
	case "tcp_retransmit":
		return "TCP retry"
	case "oom":
		return "OOM"
	default:
		return terminal.Clean(s)
	}
}
func latency(ns uint64) string {
	if ns == 0 {
		return "—"
	}
	if ns < 1e6 {
		return fmt.Sprintf("%.1fµs", float64(ns)/1e3)
	}
	if ns < 1e9 {
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", float64(ns)/1e6), "0"), ".") + "ms"
	}
	return fmt.Sprintf("%.2fs", float64(ns)/1e9)
}
