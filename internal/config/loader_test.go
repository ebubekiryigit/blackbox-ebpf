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

func TestConfigurationPrecedenceAndStrictParsing(t *testing.T) {
	cases := []struct {
		name, yaml, flag string
		history          time.Duration
		fail             bool
	}{
		{name: "defaults only", history: Default().History},
		{name: "empty YAML mapping uses defaults", yaml: "{}\n", history: Default().History},
		{name: "empty nested mapping uses defaults", yaml: "auto_capture: {}\n", history: Default().History},
		{name: "YAML overrides defaults", yaml: "history: 2m\n", history: 2 * time.Minute},
		{name: "provided flag overrides YAML", yaml: "history: 2m\n", flag: "3m", history: 3 * time.Minute},
		{name: "unprovided flag preserves YAML", yaml: "history: 2m\n", history: 2 * time.Minute},
		{name: "unknown key", yaml: "histroy: 2m", fail: true},
		{name: "version key is not part of the initial schema", yaml: "version: 1", fail: true},
		{name: "nested unknown key", yaml: "thresholds:\n  mystery: 2", fail: true},
		{name: "duplicate key", yaml: "history: 2m\nhistory: 3m", fail: true},
		{name: "nested duplicate", yaml: "thresholds:\n  scheduler:\n    warn: 2ms\n    warn: 3ms", fail: true},
		{name: "invalid duration type", yaml: "history: 120", fail: true},
		{name: "invalid string type", yaml: "log_level: 123", fail: true},
		{name: "socket is CLI-only", yaml: "socket: /tmp/blackbox.sock", fail: true},
		{name: "invalid boolean", yaml: "strict: yes", fail: true},
		{name: "invalid integer", yaml: "thresholds:\n  block_io:\n    warn: 20", fail: true},
		{name: "empty byte quantity", yaml: "max_memory: ''", fail: true},
		{name: "anchors", yaml: "history: &h 2m", fail: true},
		{name: "semantic value may be overridden", yaml: "history: 0s", flag: "3m", history: 3 * time.Minute},
		{name: "semantic failure", yaml: "history: 0s", fail: true},
		{name: "two documents", yaml: "history: 2m\n---\nhistory: 3m", fail: true},
		{name: "empty second document", yaml: "history: 2m\n---\n", fail: true},
		{name: "wrong case", yaml: "History: 2m", fail: true},
		{name: "null", yaml: "history: null", fail: true},
		{name: "malformed YAML", yaml: "version: [", fail: true},
		{name: "bad file cannot be rescued by flag", yaml: "history: false", flag: "3m", fail: true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			flags.Duration("history", Default().History, "")
			flags.SetAnnotation("history", FlagKey, []string{"history"})
			if tt.flag != "" {
				if err := flags.Set("history", tt.flag); err != nil {
					t.Fatal(err)
				}
			}
			path := ""
			if tt.yaml != "" {
				path = filepath.Join(t.TempDir(), "config.yml")
				if err := os.WriteFile(path, []byte(tt.yaml), 0600); err != nil {
					t.Fatal(err)
				}
			}
			c, err := Load(path, flags)
			if (err != nil) != tt.fail {
				t.Fatalf("config=%+v error=%v", c, err)
			}
			if !tt.fail && c.History != tt.history {
				t.Fatalf("history=%s want=%s", c.History, tt.history)
			}
		})
	}
}
func TestExplicitFalseAndNestedFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("strict: true\nmax_memory: 16MiB\nsensors: [tcp]\nthresholds:\n  block_io:\n    warn: 42ms\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f := pflag.NewFlagSet("test", pflag.ContinueOnError)
	f.Bool("strict", false, "")
	f.SetAnnotation("strict", FlagKey, []string{"strict"})
	f.Set("strict", "false")
	f.Duration("block-io-warn", Default().BlockThreshold, "")
	f.SetAnnotation("block-io-warn", FlagKey, []string{"thresholds.block_io.warn"})
	f.Set("block-io-warn", "50ms")
	c, err := Load(path, f)
	if err != nil {
		t.Fatal(err)
	}
	if c.Strict || c.MaxMemory != 16<<20 || c.BlockThreshold != 50*time.Millisecond || !reflect.DeepEqual(c.Enabled, []string{"tcp"}) {
		t.Fatalf("wrong merge: %+v", c)
	}
}
func TestYAMLRoundTripAndLocalIsolation(t *testing.T) {
	t.Setenv("BLACKBOX_HISTORY", "1h")
	c := Default()
	c.LogLevel = "debug"
	c.History = 2 * time.Minute
	c.MaxMemory = 64 << 20
	c.Enabled = []string{"scheduler", "oom"}
	c.Strict = true
	c.Resources.PollInterval = 2 * time.Second
	c.Control.Timeout = 45 * time.Second
	c.Control.QueryTimeout = 45 * time.Second
	c.BlockThreshold = 60 * time.Millisecond
	c.BlockCritical = 300 * time.Millisecond
	c.SchedulerThreshold = 30 * time.Millisecond
	c.SchedulerCritical = 150 * time.Millisecond
	b, err := YAML(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "2m0s") {
		t.Fatalf("duration output is unnecessarily verbose:\n%s", b)
	}
	path := filepath.Join(t.TempDir(), "config.yml")
	os.WriteFile(path, b, 0600)
	got, err := Load(path, nil)
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("round trip: %+v %v\n%s", got, err, b)
	}
	fresh, err := Load("", nil)
	if err != nil || !reflect.DeepEqual(fresh, Default()) {
		t.Fatal("loader state or environment leaked")
	}
}
func TestRejectEmptyAndOversizedConfig(t *testing.T) {
	for _, b := range []string{"", "# comment only\n", strings.Repeat(" ", MaxConfigBytes+1)} {
		path := filepath.Join(t.TempDir(), "config.yml")
		os.WriteFile(path, []byte(b), 0600)
		if _, err := Load(path, nil); err == nil {
			t.Fatal("invalid file accepted")
		}
	}
}
