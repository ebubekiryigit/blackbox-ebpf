package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
)

func TestOperatorConfigKeepsImplementationBudgetsPrivate(t *testing.T) {
	for _, group := range []string{"resources:\n  ring_bytes: 65536", "control:\n  max_clients: 1", "capture:\n  max_entries: 3", "report:\n  events: 1", "detail_rate: 1"} {
		t.Run(strings.Split(group, ":")[0], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(path, []byte(group+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path, nil); err == nil {
				t.Fatal("implementation setting accepted as operator configuration")
			}
		})
	}
}

func TestOperatorThresholdAndPollingPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	content := "log_level: warn\npoll_interval: 2s\ntimeout: 10s\nthresholds:\n  block_io:\n    warn: 60ms\n    critical: 300ms\n  scheduler:\n    warn: 30ms\n    critical: 150ms\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	AddFlags(flags)
	if err := flags.Set("block-io-warn", "70ms"); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path, flags)
	if err != nil {
		t.Fatal(err)
	}
	if c.BlockThreshold != 70*time.Millisecond || c.SchedulerThreshold != 30*time.Millisecond || c.Resources.PollInterval != 2*time.Second || c.Control.Timeout != 10*time.Second || c.Control.QueryTimeout != 10*time.Second {
		t.Fatalf("operator merge failed: %+v", c)
	}
	b, err := YAML(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"resources:", "control:", "capture:", "report:", "detail_rate:"} {
		if strings.HasPrefix(string(b), private) || strings.Contains(string(b), "\n"+private) {
			t.Fatalf("effective config exposes %s", private)
		}
	}
}
