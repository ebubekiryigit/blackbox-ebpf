//go:build linux && integration

package integration

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/analyzer"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/app"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/capture"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/control"
)

func TestKernelDaemonSnapshotAnalyze(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and a BTF-enabled Linux kernel")
	}
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Socket = filepath.Join(dir, "control.sock")
	cfg.History = 10 * time.Second
	cfg.Strict = true
	// Non-default sizes exercise the actual map creation and persistence path.
	cfg.Resources.RingBytes = 128 << 10
	cfg.Resources.BlockTrackingEntries = 4096
	cfg.Resources.SchedulerTrackingEntries = 8192
	cfg.Resources.PollInterval = 500 * time.Millisecond
	cfg.Resources.SegmentInterval = 500 * time.Millisecond
	cfg.BlockThreshold = time.Microsecond
	cfg.SchedulerThreshold = time.Microsecond
	cfg.BlockCritical = 2 * time.Microsecond
	cfg.SchedulerCritical = 2 * time.Microsecond
	engine, err := app.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	run := make(chan error, 1)
	serve := make(chan error, 1)
	go func() { run <- engine.Run(ctx) }()
	go func() { serve <- control.Serve(ctx, cfg.Socket, engine) }()
	defer func() {
		cancel()
		if er := <-run; er != nil {
			t.Error(er)
		}
		if er := <-serve; er != nil {
			t.Error(er)
		}
	}()
	for i := 0; i < 100; i++ {
		conn, er := net.DialTimeout("unix", cfg.Socket, 20*time.Millisecond)
		if er == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
		if i == 99 {
			t.Fatal("socket not ready")
		}
	}
	// Small ephemeral writes and active TCP resets exercise actual host hooks.
	f, err := os.Create(filepath.Join(dir, "io-workload"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data := make([]byte, 64<<10)
	for i := 0; i < 16; i++ {
		if _, err = f.Write(data); err != nil {
			t.Fatal(err)
		}
		if err = f.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for i := 0; i < 8; i++ {
		client, er := net.Dial("tcp4", listener.Addr().String())
		if er != nil {
			t.Fatal(er)
		}
		server, er := listener.Accept()
		if er != nil {
			t.Fatal(er)
		}
		_ = client.(*net.TCPConn).SetLinger(0)
		client.Close()
		server.Close()
	}
	// Exercise the IPv6 schema against the actual socket CO-RE reads.
	ipv6, er := net.Listen("tcp6", "[::1]:0")
	if er != nil {
		t.Fatalf("IPv6 loopback required by this integration scenario: %v", er)
	}
	client6, er := net.Dial("tcp6", ipv6.Addr().String())
	if er != nil {
		t.Fatal(er)
	}
	server6, er := ipv6.Accept()
	if er != nil {
		t.Fatal(er)
	}
	resetSource6 := *client6.LocalAddr().(*net.TCPAddr)
	resetDestination6 := *client6.RemoteAddr().(*net.TCPAddr)
	_ = client6.(*net.TCPConn).SetLinger(0)
	client6.Close()
	server6.Close()
	ipv6.Close()
	time.Sleep(2100 * time.Millisecond)
	status, err := control.Call(ctx, cfg.Socket, control.Request{Operation: "status"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status.Health == nil || len(status.Health.Sensors) != 4 {
		t.Fatal("missing sensor status")
	}
	var encoded bytes.Buffer
	if _, err = control.Call(ctx, cfg.Socket, control.Request{Operation: "snapshot", LastNS: int64(10 * time.Second)}, &encoded); err != nil {
		t.Fatal(err)
	}
	recorded, err := (capture.Container{}).Read(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if recorded.Manifest.Settings.PollIntervalNS != uint64(cfg.Resources.PollInterval) || recorded.Manifest.Settings.RingBytes != cfg.Resources.RingBytes || recorded.Manifest.Settings.BlockCriticalNS != uint64(cfg.BlockCritical) || recorded.Manifest.Settings.SchedulerCriticalNS != uint64(cfg.SchedulerCritical) {
		t.Fatal("effective recorder settings were not persisted")
	}
	if status.Settings == nil || status.Settings.HistoryNS != uint64(cfg.History) {
		t.Fatal("daemon did not advertise its configured history")
	}
	report := analyzer.Analyze(recorded)
	var critical uint64
	for _, s := range report.Signals {
		if !s.Available {
			t.Fatalf("sensor unavailable: %s", s.Family)
		}
		if (s.Family == "block_io" || s.Family == "scheduler") && s.Count == 0 {
			t.Fatalf("no actual %s observations", s.Family)
		}
		if s.Family == "tcp" && s.Resets == 0 {
			t.Fatal("no actual TCP reset observations")
		}
		if s.Critical > s.Anomalies || s.Anomalies > s.Count {
			t.Fatalf("invalid latency counters: %+v", s)
		}
		critical += s.Critical
		t.Logf("%s count=%d anomalies=%d critical=%d resets=%d coverage=%.2fs", s.Family, s.Count, s.Anomalies, s.Critical, s.Resets, float64(s.CoveredNS)/1e9)
	}
	if critical == 0 || report.Assessment.Severity != "critical" {
		t.Fatal("critical latency aggregate did not survive daemon, snapshot and analysis")
	}
	seenSent6, seenReceived6 := false, false
	for _, ev := range report.Timeline {
		if ev.Type == "tcp_reset" && ev.SourceIP == resetSource6.IP.String() && ev.DestinationIP == resetDestination6.IP.String() && ev.SourcePort == uint16(resetSource6.Port) && ev.DestinationPort == uint16(resetDestination6.Port) {
			if ev.EndpointSource != "socket" || ev.SocketContext != "socket" || ev.PID != 0 || ev.TGID != 0 || ev.Comm != "" {
				t.Fatalf("TCP provenance or ownership changed through snapshot/capture: %+v", ev)
			}
			seenSent6 = seenSent6 || ev.TCPDirection == "sent"
			seenReceived6 = seenReceived6 || ev.TCPDirection == "received"
		}
	}
	if !seenSent6 || !seenReceived6 {
		t.Fatalf("IPv6 reset tuple/direction missing after capture read: sent=%v received=%v", seenSent6, seenReceived6)
	}
	if len(report.Timeline) == 0 {
		t.Fatal("no anomaly details")
	}
	for _, s := range recorded.Manifest.Health.Sensors {
		t.Logf("%s kernel_bytes=%d known=%v loss=%+v", s.Name, s.KernelBytes, s.KernelBytesKnown, s.Loss)
	}
	if recorded.Manifest.Mode != "ebpf" {
		t.Fatal("real recording mislabeled")
	}
}
