package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestAutomaticConfigValidation(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		valid      bool
	}{
		{"defaults from old file", "history: 5m", true},
		{"fits exactly", "history: 70s", true},
		{"short history retains partial coverage", "history: 1s", true},
		{"relative directory", "auto_capture:\n  directory: auto", false},
		{"unknown source", "auto_capture:\n  sensors: [tcp]", false},
		{"duplicate source", "auto_capture:\n  sensors: [oom, oom]", false},
		{"empty sources", "auto_capture:\n  sensors: []", false},
		{"inactive sources", "sensors: [tcp]\nauto_capture:\n  sensors: [oom]", true},
		{"zero before", "auto_capture:\n  before: 0s", false},
		{"negative after", "auto_capture:\n  after: -1s", false},
		{"zero after", "auto_capture:\n  after: 0s", true},
		{"file count zero", "auto_capture:\n  max_files: 0", false},
		{"file count max", "auto_capture:\n  max_files: 10000", true},
		{"file count over max", "auto_capture:\n  max_files: 10001", false},
		{"storage min", "auto_capture:\n  max_storage: 1MiB", true},
		{"storage max", "auto_capture:\n  max_storage: 1024GiB", true},
		{"storage over max", "auto_capture:\n  max_storage: 1025GiB", false},
		{"storage below min", "auto_capture:\n  max_storage: 1023KiB", false},
		{"string count", "auto_capture:\n  max_files: '2'", false},
		{"fractional count", "auto_capture:\n  max_files: 2.5", false},
		{"numeric storage", "auto_capture:\n  max_storage: 1048576", false},
		{"invalid bytes", "auto_capture:\n  max_storage: 1.5MiB", false},
		{"duplicate key", "auto_capture:\n  enabled: true\n  enabled: false", false},
		{"unknown nested key", "auto_capture:\n  max_file: 2", false},
		{"null group", "auto_capture: null", false},
		{"multiple documents", "auto_capture:\n  enabled: true\n---\n", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeSettingFile(t, tt.body+"\n"), nil)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v error=%v", tt.valid, err)
			}
		})
	}
}
func TestEveryPublicFieldHasPrecedenceCoverage(t *testing.T) {
	_, keys := schemaKeys(reflect.TypeFor[fileConfig](), "")
	covered := map[string]bool{}
	for _, tt := range publicSettingCases {
		covered[tt.key] = true
	}
	for _, key := range keys {
		if !covered[key] {
			t.Fatalf("missing YAML/flag precedence test: %s", key)
		}
	}
	c := Default()
	c.AutoCapture.Sensors[0] = "changed"
	if strings.Join(Default().AutoCapture.Sensors, ",") == strings.Join(c.AutoCapture.Sensors, ",") {
		t.Fatal("automatic defaults share memory")
	}
}

func TestShortHistoryDoesNotRejectAutomaticCapture(t *testing.T) {
	path := writeSettingFile(t, "history: 1s\nauto_capture:\n  enabled: true\n  before: 1m\n  after: 10s\n")
	c, err := Load(path, nil)
	if err != nil || !c.AutoCapture.Enabled {
		t.Fatal("short history rejected", err)
	}
	path = writeSettingFile(t, "auto_capture:\n  enabled: true\n  unknown: true\n")
	if _, err = Load(path, nil); err == nil {
		t.Fatal("unknown setting bypassed strict parsing")
	}
}
