package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/control"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/terminal"
)

func TestStatusReturnsFailureWhenNoSensorIsActive(t *testing.T) {
	for _, mode := range []string{"human", "json"} {
		t.Run(mode, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "bbx-status-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			socket := filepath.Join(dir, "c.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				var request control.Request
				if err = json.NewDecoder(conn).Decode(&request); err == nil {
					response := control.Response{
						Version: model.ProtocolVersion,
						Health: &model.Health{
							Sensors:        []model.SensorHealth{{Name: "scheduler", State: "error", Reason: "reader failed"}},
							RetainedFromNS: uint64(time.Hour),
							RetainedSpanNS: uint64(2*time.Minute + 21*time.Second),
						},
						Settings: &model.RecordingSettings{HistoryNS: uint64(24 * time.Hour)},
					}
					err = json.NewEncoder(conn).Encode(response)
				}
				done <- err
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := New()
			cmd.SetContext(ctx)
			var output bytes.Buffer
			cmd.SetOut(&output)
			args := []string{"status", "--socket", socket, "--color=never"}
			if mode == "json" {
				args = append(args, "--json")
			}
			cmd.SetArgs(args)
			err = cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "no active sensors") {
				t.Fatalf("unhealthy recorder returned success: %v", err)
			}
			if mode == "json" {
				var health model.Health
				if err := json.Unmarshal(output.Bytes(), &health); err != nil || len(health.Sensors) != 1 || health.Sensors[0].State != "error" || health.RetainedSpanNS != uint64(2*time.Minute+21*time.Second) {
					t.Fatalf("machine-readable degraded health was lost: %v %s", err, output.String())
				}
			} else if !strings.Contains(output.String(), "NO ACTIVE SENSORS") || !strings.Contains(output.String(), "history target 24h") {
				t.Fatalf("status details were not rendered:\n%s", output.String())
			}
			if serverErr := <-done; serverErr != nil {
				t.Fatal(serverErr)
			}
		})
	}
}

func TestStatusIncludesAutomaticCaptureHealth(t *testing.T) {
	h := model.Health{Sensors: []model.SensorHealth{{Name: "scheduler", State: "healthy"}}, AutoCapture: &model.AutoCaptureHealth{State: "writing", Directory: "/captures/auto", Sensors: []string{"scheduler"}, Detected: 3, Saved: 2, Failures: 1, PendingUntilNS: uint64(time.Hour), PendingForNS: uint64(5 * time.Second), LastPath: "/captures/auto/incident.bbx", LastError: "storage unavailable"}}
	var out bytes.Buffer
	if err := renderStatus(&out, h, nil, terminal.Theme{}, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"AUTOMATIC CAPTURES", "State: writing", "storage unavailable", "Detected 3 · saved 2", "Window ends in 5s", "COLLECTION NOTES"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %s: %s", want, out.String())
		}
	}
}

func TestStatusShowsClockDiscontinuityAndCurrentRealtime(t *testing.T) {
	now := time.Date(2026, 9, 28, 7, 4, 7, 0, time.UTC)
	h := model.Health{Sensors: []model.SensorHealth{{Name: "scheduler", State: "healthy"}}, ObservedAt: &now, ClockChanges: 1, LastClockChange: &model.ClockDiscontinuity{DetectedBootNS: 200, DetectedAt: now.Add(-time.Minute), OffsetChangeNS: int64(14 * time.Hour)}}
	var out bytes.Buffer
	if err := renderStatus(&out, h, nil, terminal.Theme{}, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"COLLECTION NOTES", "CLOCK", "1 wall-clock discontinuity detected", "offset change 14h0m0s", "Current UTC (realtime): 2026-09-28 07:04:07"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("status omitted %q:\n%s", want, out.String())
		}
	}
}

func TestStatusShowsPartialCoverageAndLifetimeCounters(t *testing.T) {
	h := model.Health{
		Sensors: []model.SensorHealth{
			{Name: "block_io", State: "error", Reason: "BPF program unavailable", Loss: model.Counters{Unmatched: 54}, KernelBytesKnown: true, KernelBytes: 1 << 20, BookkeepingCompletions: 384},
			{Name: "scheduler", State: "healthy"},
			{Name: "tcp", State: "disabled"},
		},
		RetainedBytes: 8 << 20, MaxBytes: 32 << 20,
		IngressDrops: 2, RecorderDrops: 3, MetadataFailures: 4, SnapshotFailures: 1,
	}
	for _, tc := range []struct {
		name    string
		verbose bool
		want    []string
		absent  []string
	}{
		{
			name:   "operator summary",
			want:   []string{"RECORDER ACTIVE · COLLECTION NOTES", "1 / 2 enabled sensors recording", "Block I/O — Coverage error", "BPF program unavailable", "Scheduler — Recording", "TCP — Disabled by configuration", "54 I/O completions could not be timed", "Some observations were dropped", "4 process identities could not be resolved", "snapshot writes failed", "--verbose: lifetime counters"},
			absent: []string{"DIAGNOSTICS · SINCE DAEMON START"},
		},
		{
			name:    "verbose diagnostics",
			verbose: true,
			want:    []string{"DIAGNOSTICS · SINCE DAEMON START", "Buffer rejected", "Start missing", "384 zero-byte logical WRITE completions", "Ingress detail drops", "Memory history evictions"},
			absent:  []string{"--verbose: lifetime counters"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := renderStatus(&out, h, nil, terminal.Theme{Width: 120}, tc.verbose); err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("status omitted %q:\n%s", want, out.String())
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(out.String(), absent) {
					t.Fatalf("status included %q:\n%s", absent, out.String())
				}
			}
		})
	}
}

func TestStatusShowsRetainedSpanWithoutClaimingCoverage(t *testing.T) {
	h := model.Health{
		Sensors:         []model.SensorHealth{{Name: "scheduler", State: "healthy"}},
		RetainedFromNS:  uint64(time.Hour),
		RetainedSpanNS:  uint64(2*time.Minute + 21*time.Second),
		RetainedBytes:   31 << 20,
		MaxBytes:        32 << 20,
		EvictedSegments: 458,
	}
	settings := &model.RecordingSettings{HistoryNS: uint64(24 * time.Hour)}
	var out bytes.Buffer
	if err := renderStatus(&out, h, settings, terminal.Theme{}, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"RECORDER ACTIVE", "Oldest retained segment: 2m21s ago", "history target 24h"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("status omitted %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "2m21s monitored") || strings.Contains(out.String(), "COLLECTION NOTES") {
		t.Fatalf("retention age was mistaken for sensor coverage or loss:\n%s", out.String())
	}
	out.Reset()
	h.RetainedSpanNS = 0 // An older daemon does not send this additive field.
	if err := renderStatus(&out, h, settings, terminal.Theme{}, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Oldest retained segment:") {
		t.Fatalf("missing retention age was presented as zero:\n%s", out.String())
	}
}
