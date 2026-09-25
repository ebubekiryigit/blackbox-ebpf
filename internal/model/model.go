// Package model is the durable boundary shared by recording and offline analysis.
package model

import "time"

var Families = []string{"block_io", "scheduler", "tcp", "oom"}

// Bucket upper bounds are 1ms, 2ms, ... 512ms; the final bucket is unbounded.
type Histogram [HistogramBuckets]uint64

func (h Histogram) Count() (n uint64) {
	for _, v := range h {
		n += v
	}
	return
}

type Event struct {
	MonoNS          uint64 `json:"mono_ns"`
	Type            string `json:"type"`
	PID             uint32 `json:"pid,omitempty"`
	TGID            uint32 `json:"tgid,omitempty"`
	Comm            string `json:"comm,omitempty"`
	ProcessStartNS  uint64 `json:"process_start_ns,omitempty"`
	CgroupID        uint64 `json:"cgroup_id,omitempty"`
	CPU             uint32 `json:"cpu"`
	LatencyNS       uint64 `json:"latency_ns,omitempty"`
	Major           uint32 `json:"major,omitempty"`
	Minor           uint32 `json:"minor,omitempty"`
	Bytes           uint64 `json:"bytes,omitempty"`
	Operation       string `json:"operation,omitempty"`
	SourceIP        string `json:"source_ip,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	SourcePort      uint16 `json:"source_port,omitempty"`
	DestinationPort uint16 `json:"destination_port,omitempty"`
	State           uint32 `json:"state,omitempty"`
	TCPDirection    string `json:"tcp_direction,omitempty"`
	SocketContext   string `json:"socket_context,omitempty"`
	EndpointSource  string `json:"endpoint_source,omitempty"`
	CgroupPath      string `json:"cgroup_path,omitempty"`
}

type Counters struct {
	RingFailures     uint64 `json:"ring_reserve_failures"`
	Suppressed       uint64 `json:"detail_suppressed"`
	TrackingFailures uint64 `json:"tracking_failures"`
	Unmatched        uint64 `json:"unmatched_completions"`
	DecodeFailures   uint64 `json:"detail_decode_failures,omitempty"`
}
type Metric struct {
	// Zero-byte logical WRITE completion notifications are not device I/O or loss.
	BookkeepingCompletions uint64    `json:"bookkeeping_completions,omitempty"`
	Family                 string    `json:"family"`
	StartMonoNS            uint64    `json:"start_mono_ns"`
	EndMonoNS              uint64    `json:"end_mono_ns"`
	Histogram              Histogram `json:"histogram"`
	Count                  uint64    `json:"count"`
	Anomalies              uint64    `json:"anomalies"`
	Critical               uint64    `json:"critical_latency,omitempty"`
	Bytes                  uint64    `json:"bytes"`
	Retransmits            uint64    `json:"retransmits"`
	Resets                 uint64    `json:"resets"`
	Loss                   Counters  `json:"loss"`
}
type Segment struct {
	StartMonoNS uint64   `json:"start_mono_ns"`
	EndMonoNS   uint64   `json:"end_mono_ns"`
	Events      []Event  `json:"events,omitempty"`
	Metrics     []Metric `json:"metrics,omitempty"`
}
type SensorHealth struct {
	BookkeepingCompletions uint64   `json:"bookkeeping_completions,omitempty"`
	KernelBytes            uint64   `json:"kernel_bytes,omitempty"`
	KernelBytesKnown       bool     `json:"kernel_bytes_known"`
	Name                   string   `json:"name"`
	State                  string   `json:"state"`
	Reason                 string   `json:"reason,omitempty"`
	Loss                   Counters `json:"loss"`
}
type Health struct {
	AutoCapture      *AutoCaptureHealth `json:"auto_capture,omitempty"`
	Sensors          []SensorHealth     `json:"sensors"`
	IngressDrops     uint64             `json:"ingress_drops"`
	RecorderDrops    uint64             `json:"recorder_drops"`
	EvictedSegments  uint64             `json:"memory_evicted_segments"`
	MetadataFailures uint64             `json:"metadata_resolution_failures"`
	SnapshotFailures uint64             `json:"snapshot_write_failures"`
	RetainedBytes    int64              `json:"retained_bytes"`
	MaxBytes         int64              `json:"max_bytes"`
	RetainedFromNS   uint64             `json:"retained_from_ns"`
}
type Host struct {
	Hostname     string    `json:"hostname"`
	Kernel       string    `json:"kernel"`
	Architecture string    `json:"architecture"`
	BootID       string    `json:"boot_id"`
	AnchorMonoNS uint64    `json:"anchor_mono_ns"`
	AnchorWall   time.Time `json:"anchor_wall"`
}

func (h Host) Wall(ns uint64) time.Time {
	return h.AnchorWall.Add(time.Duration(int64(ns) - int64(h.AnchorMonoNS)))
}

type RecordingSettings struct {
	PollIntervalNS           uint64   `json:"poll_interval_ns,omitempty"`
	SegmentIntervalNS        uint64   `json:"segment_interval_ns,omitempty"`
	IngressEvents            int      `json:"ingress_events,omitempty"`
	MetadataEntries          int      `json:"metadata_entries,omitempty"`
	BlockTrackingEntries     uint32   `json:"block_tracking_entries,omitempty"`
	SchedulerTrackingEntries uint32   `json:"scheduler_tracking_entries,omitempty"`
	RingBytes                uint32   `json:"ring_bytes,omitempty"`
	HistoryNS                uint64   `json:"history_ns"`
	MaxMemory                int64    `json:"max_memory"`
	BlockThresholdNS         uint64   `json:"block_threshold_ns"`
	SchedulerThresholdNS     uint64   `json:"scheduler_threshold_ns"`
	BlockCriticalNS          uint64   `json:"block_critical_ns,omitempty"`
	SchedulerCriticalNS      uint64   `json:"scheduler_critical_ns,omitempty"`
	DetailRate               uint32   `json:"detail_rate"`
	Enabled                  []string `json:"enabled_sensors"`
	Strict                   bool     `json:"strict"`
}

type Manifest struct {
	AutoIncident         *AutoIncident     `json:"auto_incident,omitempty"`
	RecordingStartMonoNS uint64            `json:"recording_start_mono_ns,omitempty"`
	Settings             RecordingSettings `json:"settings"`
	FormatVersion        int               `json:"capture_format_version"`
	ApplicationVersion   string            `json:"application_version"`
	StartMonoNS          uint64            `json:"start_mono_ns"`
	EndMonoNS            uint64            `json:"end_mono_ns"`
	RequestedStartMonoNS uint64            `json:"requested_start_mono_ns"`
	Mode                 string            `json:"mode"`
	Health               Health            `json:"health"`
}
type Capture struct {
	Manifest Manifest  `json:"manifest"`
	Host     Host      `json:"host"`
	Segments []Segment `json:"segments"`
}
