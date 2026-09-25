//go:build linux && integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/analyzer"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/app"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/capture"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
)

func TestKernelAutomaticCapture(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires privileged Linux with BTF")
	}
	cfg := config.Default()
	cfg.Enabled = []string{"block_io", "scheduler"}
	cfg.Strict = true
	cfg.History = 3 * time.Second
	cfg.Resources.PollInterval = 100 * time.Millisecond
	cfg.AutoCapture.Directory = filepath.Join(t.TempDir(), "automatic")
	cfg.AutoCapture.Before = time.Second
	cfg.AutoCapture.After = 500 * time.Millisecond
	cfg.BlockThreshold = time.Microsecond
	cfg.BlockCritical = 2 * time.Microsecond
	cfg.SchedulerThreshold = time.Microsecond
	cfg.SchedulerCritical = 2 * time.Microsecond
	e, err := app.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	if _, err = e.Ask(ctx, 0); err != nil {
		t.Fatal(err)
	}
	// Bounded fsync work on a disposable file plus runnable scheduling activity.
	f, err := os.CreateTemp(t.TempDir(), "workload")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data := make([]byte, 64<<10)
	for i := 0; i < 24; i++ {
		if _, err = f.Write(data); err != nil {
			t.Fatal(err)
		}
		if err = f.Sync(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	for {
		r, err := e.Ask(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		h := r.Health.AutoCapture
		if h.Failures > 0 {
			t.Fatalf("automatic publication failed: %+v", h)
		}
		if h.Saved > 0 {
			c, err := capture.ReadFile(h.LastPath)
			if err != nil {
				t.Fatal(err)
			}
			if c.Manifest.Mode != "ebpf" || c.Manifest.AutoIncident == nil || len(c.Manifest.AutoIncident.Triggers) == 0 {
				t.Fatal("real capture lost trigger metadata")
			}
			if c.Manifest.EndMonoNS-c.Manifest.AutoIncident.DetectedMonoNS != uint64(cfg.AutoCapture.After) {
				t.Fatal("post-window moved")
			}
			report := analyzer.Analyze(c)
			if report.Assessment.SignalState == "clear" {
				t.Fatal("critical trigger reported clear")
			}
			t.Logf("automatic capture=%s triggers=%+v assessment=%s", h.LastPath, c.Manifest.AutoIncident.Triggers, report.Assessment.Code)
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("no automatic capture:", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}
