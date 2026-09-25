// Package config owns validated operational settings and their defaults.
package config

import (
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

type Config struct {
	LogLevel           string
	History            time.Duration
	MaxMemory          int64
	Socket             string
	BlockThreshold     time.Duration
	SchedulerThreshold time.Duration
	BlockCritical      time.Duration
	SchedulerCritical  time.Duration
	DetailRate         uint32
	Strict             bool
	Enabled            []string
	Resources          Resources
	Control            Control
	Capture            CaptureLimits
	Report             Report
	AutoCapture        AutoCapture
}

func (c Config) Validate() error {
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be debug, info, warn, or error")
	}
	if c.History < MinHistory || c.History > MaxHistory {
		return fmt.Errorf("history must be between %s and %s", MinHistory, MaxHistory)
	}
	if c.MaxMemory < MinMemory || c.MaxMemory > MaxMemory {
		return fmt.Errorf("max-memory must be between %s and %s", MemoryText(MinMemory), MemoryText(MaxMemory))
	}
	if !path.IsAbs(c.Socket) || strings.ContainsRune(c.Socket, 0) || len(c.Socket) > MaxSocketBytes {
		return fmt.Errorf("socket must be an absolute Unix path of at most %d bytes", MaxSocketBytes)
	}
	if c.BlockThreshold <= 0 || c.SchedulerThreshold <= 0 {
		return fmt.Errorf("latency thresholds must be positive")
	}
	if c.BlockCritical <= c.BlockThreshold || c.SchedulerCritical <= c.SchedulerThreshold {
		return fmt.Errorf("each critical latency threshold must be greater than its warn threshold")
	}
	if c.DetailRate < 1 || c.DetailRate > MaxDetailRate {
		return fmt.Errorf("detail-rate must be between 1 and %d per sensor per second", MaxDetailRate)
	}
	if len(c.Enabled) == 0 {
		return fmt.Errorf("at least one sensor must be enabled")
	}
	seen := map[string]bool{}
	for _, n := range c.Enabled {
		valid := false
		for _, f := range model.Families {
			valid = valid || n == f
		}
		if !valid || seen[n] {
			return fmt.Errorf("invalid or duplicate sensor %q", n)
		}
		seen[n] = true
	}
	r := c.Resources
	for name, n := range ordered(map[string]int{"ingress_events": r.IngressEvents, "query_queue": r.QueryQueue, "metadata_entries": r.MetadataEntries}) {
		if n < 1 || n > MaxQueueEntries {
			return fmt.Errorf("resources.%s must be between 1 and %d", name, MaxQueueEntries)
		}
	}
	if r.MetadataPathBytes < 1 || r.MetadataPathBytes > MaxMetadataPathBytes {
		return fmt.Errorf("resources.metadata_path_bytes must be between 1 and %d", MaxMetadataPathBytes)
	}
	for name, n := range ordered(map[string]uint32{"block_tracking_entries": r.BlockTrackingEntries, "scheduler_tracking_entries": r.SchedulerTrackingEntries}) {
		if n < 1 || n > MaxTrackingEntries {
			return fmt.Errorf("resources.%s must be between 1 and %d", name, MaxTrackingEntries)
		}
	}
	if r.RingBytes < MinRingBytes || r.RingBytes > MaxRingBytes || r.RingBytes&(r.RingBytes-1) != 0 {
		return fmt.Errorf("resources.ring_bytes must be a power of two between %d and %d", MinRingBytes, MaxRingBytes)
	}
	for name, n := range ordered(map[string]time.Duration{"poll_interval": r.PollInterval, "segment_interval": r.SegmentInterval}) {
		if n < MinInterval || n > MaxInterval || n > c.History {
			return fmt.Errorf("resources.%s must be between %s and %s and no longer than history", name, MinInterval, MaxInterval)
		}
	}
	if err := c.Control.Validate(); err != nil {
		return err
	}
	if err := c.Capture.Validate(); err != nil {
		return err
	}
	if err := c.AutoCapture.Validate(); err != nil {
		return err
	}
	if c.Control.MaxCaptureBytes < c.Capture.MaxDecodedBytes {
		return fmt.Errorf("control.max_capture_bytes must be at least capture.max_decoded_bytes")
	}
	for name, n := range ordered(map[string]int{"events": c.Report.Events, "verbose_events": c.Report.VerboseEvents, "processes": c.Report.Processes, "verbose_processes": c.Report.VerboseProcesses}) {
		if n < 1 || n > MaxReportEvents {
			return fmt.Errorf("report.%s must be between 1 and %d", name, MaxReportEvents)
		}
	}
	return nil
}

func (a AutoCapture) Validate() error {
	if !path.IsAbs(a.Directory) || strings.ContainsRune(a.Directory, 0) || len(a.Directory) > MaxMetadataPathBytes {
		return fmt.Errorf("auto_capture.directory must be an absolute path of at most %d bytes", MaxMetadataPathBytes)
	}
	if a.Before < MinHistory || a.Before > MaxHistory || a.After < 0 || a.After > MaxHistory {
		return fmt.Errorf("auto_capture.before must be 1s–24h and after must be 0s–24h")
	}
	if a.MaxFiles < 1 || a.MaxFiles > MaxAutoFiles || a.MaxStorage < MinMemory || a.MaxStorage > MaxAutoStorage {
		return fmt.Errorf("auto_capture requires max_files between 1 and %d and max_storage between 1MiB and 1TiB", MaxAutoFiles)
	}
	if len(a.Sensors) == 0 {
		return fmt.Errorf("auto_capture.sensors must include at least one of block_io, scheduler, oom")
	}
	seen := map[string]bool{}
	for _, s := range a.Sensors {
		if (s != "block_io" && s != "scheduler" && s != "oom") || seen[s] {
			return fmt.Errorf("invalid or duplicate auto_capture sensor %q (supported: block_io, scheduler, oom)", s)
		}
		seen[s] = true
	}
	return nil
}
func (c Control) Validate() error {
	if c.MaxClients < 1 || c.MaxClients > MaxControlClients {
		return fmt.Errorf("control.max_clients must be between 1 and %d", MaxControlClients)
	}
	for name, n := range ordered(map[string]int{"request_bytes": c.RequestBytes, "response_bytes": c.ResponseBytes}) {
		if n < MinHeaderBytes || n > MaxHeaderBytes {
			return fmt.Errorf("control.%s must be between %d and %d", name, MinHeaderBytes, MaxHeaderBytes)
		}
	}
	if c.Timeout < MinControlTimeout || c.Timeout > MaxControlTimeout {
		return fmt.Errorf("control.timeout must be between %s and %s", MinControlTimeout, MaxControlTimeout)
	}
	for name, n := range ordered(map[string]time.Duration{"query_timeout": c.QueryTimeout, "dial_timeout": c.DialTimeout}) {
		if n < MinInterval || n > c.Timeout {
			return fmt.Errorf("control.%s must be between %s and control.timeout", name, MinInterval)
		}
	}
	if c.MaxCaptureBytes < MinMemory || c.MaxCaptureBytes > MaxCaptureBytes {
		return fmt.Errorf("control.max_capture_bytes must be between %s and %s", MemoryText(MinMemory), MemoryText(MaxCaptureBytes))
	}
	return nil
}
func (c CaptureLimits) Validate() error {
	if c.MaxDecodedBytes < MinMemory || c.MaxDecodedBytes > MaxCaptureBytes {
		return fmt.Errorf("capture.max_decoded_bytes must be between %s and %s", MemoryText(MinMemory), MemoryText(MaxCaptureBytes))
	}
	w := c.CompressionWindowBytes
	if w < MinCompressionWindowBytes || w > MaxCompressionWindowBytes || w&(w-1) != 0 || int64(w) > c.MaxDecodedBytes {
		return fmt.Errorf("capture.compression_window_bytes must be a power of two between %d and %d and no larger than max_decoded_bytes", MinCompressionWindowBytes, MaxCompressionWindowBytes)
	}
	if c.MaxEntries < 3 || c.MaxEntries > MaxCaptureEntries {
		return fmt.Errorf("capture.max_entries must be between 3 and %d", MaxCaptureEntries)
	}
	return nil
}

// Memory parses a whole binary byte quantity. Validation applies per setting.
func Memory(s string) (int64, error) {
	for _, u := range []struct {
		s string
		n int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(s, u.s) {
			n, e := strconv.ParseInt(strings.TrimSuffix(s, u.s), 10, 64)
			if e != nil || n < 0 || n > int64(^uint64(0)>>1)/u.n {
				return 0, fmt.Errorf("invalid byte quantity %q", s)
			}
			return n * u.n, nil
		}
	}
	return 0, fmt.Errorf("use a whole number with B, KiB, MiB or GiB")
}
func MemoryText(n int64) string {
	for _, u := range []struct {
		s string
		n int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if n > 0 && n%u.n == 0 {
			return fmt.Sprintf("%d%s", n/u.n, u.s)
		}
	}
	return fmt.Sprintf("%dB", n)
}

// ordered yields stable validation errors when several values are invalid.
func ordered[T any](values map[string]T) func(func(string, T) bool) {
	return func(yield func(string, T) bool) {
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			if !yield(key, values[key]) {
				return
			}
		}
	}
}
