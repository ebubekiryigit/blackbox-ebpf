package config

import (
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

// Operational defaults live here. Wire/schema invariants live in model/format.go.
// Only settings in settings.go are operator configuration. Implementation budgets
// remain here so contributors can change them in one place.
const (
	MaxConfigBytes                  = 1 << 20
	MinHistory                      = time.Second
	MaxHistory                      = 24 * time.Hour
	MinMemory                 int64 = 1 << 20
	MaxMemory                 int64 = 1 << 30
	MaxDetailRate                   = 10000
	MaxQueueEntries                 = 1 << 20
	MaxTrackingEntries              = 1 << 20
	MinRingBytes                    = 64 << 10 // Valid for supported Linux 4/16/64 KiB page sizes.
	MaxRingBytes                    = 64 << 20
	MaxControlClients               = 1024
	MaxHeaderBytes                  = 4 << 20
	MaxCaptureBytes           int64 = 1 << 30
	MaxCaptureEntries               = 1000000
	MinCompressionWindowBytes       = 64 << 10
	MaxCompressionWindowBytes       = 64 << 20
	MaxReportEvents                 = 100000
	MaxSocketBytes                  = 103
	MinHeaderBytes                  = 512
	MaxMetadataPathBytes            = 4096
	MinInterval                     = 100 * time.Millisecond
	MaxInterval                     = time.Minute
	MinControlTimeout               = time.Second
	MaxControlTimeout               = 10 * time.Minute
	DefaultCaptureDuration          = 30 * time.Second
	DefaultDemoOutput               = "demo.bbx"
)

type Resources struct {
	PollInterval             time.Duration
	SegmentInterval          time.Duration
	IngressEvents            int
	QueryQueue               int
	MetadataEntries          int
	MetadataPathBytes        int
	BlockTrackingEntries     uint32
	SchedulerTrackingEntries uint32
	RingBytes                uint32
}
type Control struct {
	MaxClients      int
	RequestBytes    int
	ResponseBytes   int
	Timeout         time.Duration
	QueryTimeout    time.Duration
	DialTimeout     time.Duration
	MaxCaptureBytes int64
}
type CaptureLimits struct {
	CompressionWindowBytes uint32
	MaxDecodedBytes        int64
	MaxEntries             int
}
type Report struct {
	Events           int
	VerboseEvents    int
	Processes        int
	VerboseProcesses int
}

func Default() Config {
	return Config{
		LogLevel: "info",
		History:  5 * time.Minute, MaxMemory: 32 << 20, Socket: "/run/blackbox/blackbox.sock",
		BlockThreshold: 50 * time.Millisecond, SchedulerThreshold: 20 * time.Millisecond,
		BlockCritical: 250 * time.Millisecond, SchedulerCritical: 100 * time.Millisecond,
		DetailRate: 256, Enabled: append([]string(nil), model.Families...),
		Resources: Resources{PollInterval: time.Second, SegmentInterval: time.Second, IngressEvents: 1024, QueryQueue: 8, MetadataEntries: 1024, MetadataPathBytes: 512, BlockTrackingEntries: 8192, SchedulerTrackingEntries: 16384, RingBytes: 256 << 10},
		Control:   Control{MaxClients: 8, RequestBytes: 4096, ResponseBytes: 64 << 10, Timeout: 30 * time.Second, QueryTimeout: 30 * time.Second, DialTimeout: time.Second, MaxCaptureBytes: 512 << 20},
		Capture:   CaptureLimits{MaxDecodedBytes: 256 << 20, MaxEntries: 100000, CompressionWindowBytes: 1 << 20},
		Report:    Report{Events: 20, VerboseEvents: 100, Processes: 5, VerboseProcesses: 10},
	}
}
