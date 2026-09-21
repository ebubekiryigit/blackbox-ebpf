package model

import "fmt"

// CounterNote gives stored counters the same meaning in status and analysis.
// Counter is a stable JSON field name; the explanation does not infer a cause.
type CounterNote struct {
	Counter            string
	Value              uint64
	Title, Explanation string
}

func CounterNotes(sensor string, c Counters) []CounterNote {
	var out []CounterNote
	add := func(counter string, n uint64, singular, plural, explanation string) {
		if n > 0 {
			title := plural
			if n == 1 {
				title = singular
			}
			out = append(out, CounterNote{counter, n, fmt.Sprintf("%d %s", n, title), explanation})
		}
	}
	if sensor == "block_io" {
		add("unmatched_completions", c.Unmatched, "I/O completion could not be timed", "I/O completions could not be timed", "No matching dispatch/start record was found (unmatched). These latencies are excluded from the I/O histogram; the capture does not establish why starts were missing.")
	} else {
		add("unmatched_completions", c.Unmatched, "completion had no matching start record", "completions had no matching start record", "Their latency could not be measured (unmatched). This is a measurement gap, not proof of a workload failure.")
	}
	add("tracking_failures", c.TrackingFailures, "start record could not be saved", "start records could not be saved", "The sensor could not retain tracking state (tracking failures). Some latency measurements may therefore be missing.")
	add("ring_reserve_failures", c.RingFailures, "event detail could not enter the kernel buffer", "event details could not enter the kernel buffer", "The detail buffer could not reserve space (ring reserve failures). Aggregate counts remain available, but these individual events cannot be inspected.")
	add("detail_suppressed", c.Suppressed, "event detail skipped by the rate limit", "event details skipped by the rate limit", "The configured detail quota was reached (detail suppressed). Aggregate counts and histograms still include these observations; individual details were intentionally omitted.")
	add("detail_decode_failures", c.DecodeFailures, "event detail could not be decoded", "event details could not be decoded", "Userspace rejected a malformed or unknown detail record. Aggregate counts and histograms remain available, but these individual events cannot be inspected.")
	return out
}
