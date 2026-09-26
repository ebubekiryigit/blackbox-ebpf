package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
)

func TestShippedExampleLoadsAsCompiledDefaults(t *testing.T) {
	path := filepath.Join("..", "..", "config.example.yml")
	got, err := Load(path, nil)
	if err != nil {
		t.Fatalf("shipped config example cannot start a daemon: %v", err)
	}
	if !reflect.DeepEqual(got, Default()) {
		t.Fatalf("shipped config drifted from compiled defaults:\ngot  %+v\nwant %+v", got, Default())
	}
}

func TestOperatorProfilesKeepCombinedSettingsAndExplicitOverrides(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		flags      map[string]string
		check      func(*testing.T, Config)
	}{
		{
			name: "bare metal with longer automatic persistence",
			yaml: `log_level: warn
history: 15m
max_memory: 64MiB
sensors: [block_io, scheduler, tcp, oom]
strict: true
poll_interval: 2s
timeout: 20s
thresholds:
  block_io:
    warn: 75ms
    critical: 300ms
  scheduler:
    warn: 30ms
    critical: 150ms
auto_capture:
  before: 2m
  after: 15s
  max_files: 250
  max_storage: 2GiB
  write_timeout: 5m
`,
			flags: map[string]string{"history": "20m", "strict": "false"},
			check: func(t *testing.T, c Config) {
				if c.LogLevel != "warn" || c.History != 20*time.Minute || c.Strict || c.MaxMemory != 64<<20 || c.Resources.PollInterval != 2*time.Second || c.Control.Timeout != 20*time.Second || c.Control.QueryTimeout != 20*time.Second || c.AutoCapture.Before != 2*time.Minute || c.AutoCapture.After != 15*time.Second || c.AutoCapture.MaxFiles != 250 || c.AutoCapture.MaxStorage != 2<<30 || c.AutoCapture.WriteTimeout != 5*time.Minute || c.BlockThreshold != 75*time.Millisecond || c.BlockCritical != 300*time.Millisecond || c.SchedulerThreshold != 30*time.Millisecond || c.SchedulerCritical != 150*time.Millisecond {
					t.Fatalf("combined bare-metal settings changed: %+v", c)
				}
			},
		},
		{
			name: "small host with partial automatic history",
			yaml: `history: 30s
max_memory: 8MiB
sensors: [tcp, oom]
poll_interval: 1s
auto_capture:
  sensors: [oom]
  before: 1m
  after: 0s
  max_files: 50
  max_storage: 128MiB
`,
			check: func(t *testing.T, c Config) {
				if !reflect.DeepEqual(c.Enabled, []string{"tcp", "oom"}) || !reflect.DeepEqual(c.AutoCapture.Sensors, []string{"oom"}) || c.AutoCapture.Before <= c.History || c.AutoCapture.After != 0 || c.AutoCapture.MaxStorage != 128<<20 || c.AutoCapture.WriteTimeout != 2*time.Minute {
					t.Fatalf("small-host partial history or defaults changed: %+v", c)
				}
			},
		},
		{
			name: "manual-only recorder",
			yaml: "sensors: [block_io, scheduler]\nauto_capture:\n  enabled: false\n",
			check: func(t *testing.T, c Config) {
				if c.AutoCapture.Enabled || !reflect.DeepEqual(c.Enabled, []string{"block_io", "scheduler"}) || c.History != Default().History {
					t.Fatalf("manual-only recorder changed: %+v", c)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := pflag.NewFlagSet("operator", pflag.ContinueOnError)
			AddConfigFlags(flags)
			for key, value := range tc.flags {
				if err := flags.Set(key, value); err != nil {
					t.Fatal(err)
				}
			}
			c, err := Load(writeSettingFile(t, tc.yaml), flags)
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, c)
		})
	}
}

func TestOperationalConfigErrorsNameTheBrokenSetting(t *testing.T) {
	for _, tc := range []struct{ name, yaml, want string }{
		{"unknown sensor", "sensors: [disk]\n", "sensor"},
		{"history shorter than polling", "history: 1s\npoll_interval: 2s\n", "poll_interval"},
		{"critical at warning", "thresholds:\n  block_io:\n    warn: 250ms\n", "critical"},
		{"invalid auto directory", "auto_capture:\n  directory: captures/auto\n", "auto_capture.directory"},
		{"unsafe auto storage", "auto_capture:\n  max_storage: 1023KiB\n", "max_storage"},
		{"invalid auto timeout", "auto_capture:\n  write_timeout: 11m\n", "auto_capture.write_timeout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeSettingFile(t, tc.yaml), nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("operator error did not identify %q: %v", tc.want, err)
			}
		})
	}
	missing := filepath.Join(t.TempDir(), "missing.yml")
	if _, err := Load(missing, nil); !os.IsNotExist(err) {
		t.Fatalf("missing explicit config did not fail clearly: %v", err)
	}
}
