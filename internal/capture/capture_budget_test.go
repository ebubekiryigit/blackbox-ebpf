package capture_test

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/capture"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/recorder"
)

// The recorder accounting and decoded archive limit use different units.
// Fill the default budget with deliberately escape-heavy, fully populated
// events so a future default/schema change cannot quietly make snapshots fail.
func TestFullRecorderBudgetFitsDefaultCapture(t *testing.T) {
	cfg := config.Default()
	now := uint64(time.Hour)
	r := recorder.NewWithSegmentInterval(24*time.Hour, cfg.RecorderBudgetBytes, time.Second, now)
	event := model.Event{
		Type: "tcp_reset", PID: ^uint32(0), TGID: ^uint32(0),
		Comm: strings.Repeat("\x01", 16), ProcessStartNS: ^uint64(0),
		CgroupID: ^uint64(0), CPU: ^uint32(0), LatencyNS: ^uint64(0),
		Major: ^uint32(0), Minor: ^uint32(0), Bytes: ^uint64(0),
		Operation: "op:65535", SourceIP: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		DestinationIP: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		SourcePort:    65535, DestinationPort: 65535, State: ^uint32(0),
		TCPDirection: "received", SocketContext: "socket", EndpointSource: "packet_header",
		CgroupPath: strings.Repeat("\x01", 512),
	}
	for i := 0; i < 100000; i++ {
		event.MonoNS = now
		if !r.Event(event, now) {
			t.Fatalf("recorder dropped event before budget filled at %d", i)
		}
		now += uint64(time.Millisecond)
		if r.Health().EvictedSegments != 0 {
			break
		}
	}
	h := r.Health()
	if h.EvictedSegments == 0 || h.RetainedBytes > cfg.RecorderBudgetBytes {
		t.Fatalf("recorder did not exercise full budget: %+v", h)
	}
	host := model.Host{ClockSource: "boottime", AnchorMonoNS: now, AnchorWall: time.Now().UTC()}
	snapshot := r.Snapshot(24*time.Hour, now, host, h, "ebpf")
	if err := (capture.Container{Limits: cfg.Capture}).Write(io.Discard, snapshot); err != nil {
		t.Fatalf("full recorder budget cannot be encoded within default .bbx limits: %v", err)
	}
}
