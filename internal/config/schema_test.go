package config

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
)

type settingCase struct {
	key, yamlValue, flag, flagValue string
	value                           func(Config) any
	wantYAML, wantFlag              any
}

var publicSettingCases = []settingCase{
	{"log_level", "debug", "log-level", "error", func(c Config) any { return c.LogLevel }, "debug", "error"},
	{"history", "2m", "history", "3m", func(c Config) any { return c.History }, 2 * time.Minute, 3 * time.Minute},
	{"max_memory", "16MiB", "max-memory", "64MiB", func(c Config) any { return c.MaxMemory }, int64(16 << 20), int64(64 << 20)},
	{"sensors", "[tcp]", "sensors", "scheduler,oom", func(c Config) any { return c.Enabled }, []string{"tcp"}, []string{"scheduler", "oom"}},
	{"strict", "true", "strict", "false", func(c Config) any { return c.Strict }, true, false},
	{"poll_interval", "2s", "poll-interval", "3s", func(c Config) any { return c.Resources.PollInterval }, 2 * time.Second, 3 * time.Second},
	{"timeout", "10s", "timeout", "20s", func(c Config) any { return c.Control.Timeout }, 10 * time.Second, 20 * time.Second},
	{"thresholds.block_io.warn", "60ms", "block-io-warn", "70ms", func(c Config) any { return c.BlockThreshold }, 60 * time.Millisecond, 70 * time.Millisecond},
	{"thresholds.block_io.critical", "300ms", "block-io-critical", "400ms", func(c Config) any { return c.BlockCritical }, 300 * time.Millisecond, 400 * time.Millisecond},
	{"thresholds.scheduler.warn", "30ms", "scheduler-warn", "40ms", func(c Config) any { return c.SchedulerThreshold }, 30 * time.Millisecond, 40 * time.Millisecond},
	{"thresholds.scheduler.critical", "150ms", "scheduler-critical", "200ms", func(c Config) any { return c.SchedulerCritical }, 150 * time.Millisecond, 200 * time.Millisecond},
}

func TestEveryPublicSettingMergesFromYAMLAndExplicitFlags(t *testing.T) {
	for _, test := range publicSettingCases {
		t.Run(test.key, func(t *testing.T) {
			path := writeSettingFile(t, nestedYAML(test.key, test.yamlValue))
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			AddConfigFlags(flags)
			fromYAML, err := Load(path, flags)
			if err != nil {
				t.Fatal(err)
			}
			if got := test.value(fromYAML); !reflect.DeepEqual(got, test.wantYAML) {
				t.Fatalf("YAML value = %#v, want %#v", got, test.wantYAML)
			}
			if err = flags.Set(test.flag, test.flagValue); err != nil {
				t.Fatal(err)
			}
			fromFlag, err := Load(path, flags)
			if err != nil {
				t.Fatal(err)
			}
			if got := test.value(fromFlag); !reflect.DeepEqual(got, test.wantFlag) {
				t.Fatalf("flag value = %#v, want %#v", got, test.wantFlag)
			}
		})
	}
}

func TestSchemaHelpAndFlagsStayInSync(t *testing.T) {
	all, leaves := schemaKeys(reflect.TypeFor[fileConfig](), "")
	wantHelp := append(append([]string(nil), all...), "socket")
	slices.Sort(wantHelp)
	gotHelp := make([]string, 0, len(settingHelp))
	for key, help := range settingHelp {
		if strings.TrimSpace(help) == "" {
			t.Fatalf("empty help for %s", key)
		}
		gotHelp = append(gotHelp, key)
	}
	slices.Sort(gotHelp)
	if !reflect.DeepEqual(gotHelp, wantHelp) {
		t.Fatalf("setting help drifted: got %v want %v", gotHelp, wantHelp)
	}
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	AddConfigFlags(flags)
	var annotations []string
	flags.VisitAll(func(flag *pflag.Flag) {
		keys := flag.Annotations[FlagKey]
		if len(keys) != 1 {
			t.Fatalf("flag %s has invalid config annotation: %v", flag.Name, keys)
		}
		annotations = append(annotations, keys[0])
	})
	slices.Sort(annotations)
	slices.Sort(leaves)
	if !reflect.DeepEqual(annotations, leaves) {
		t.Fatalf("config flags drifted: got %v want %v", annotations, leaves)
	}
}

func TestPublicSettingBoundaries(t *testing.T) {
	tests := []struct {
		name, yaml string
		valid      bool
	}{
		{"log minimum surface", "log_level: debug", true}, {"log unknown", "log_level: trace", false},
		{"history minimum", "history: 1s", true}, {"history below minimum", "history: 999ms", false}, {"history maximum", "history: 24h", true}, {"history above maximum", "history: 24h1s", false},
		{"memory minimum", "max_memory: 1MiB", true}, {"memory below minimum", "max_memory: 1023KiB", false}, {"memory maximum", "max_memory: 1GiB", true}, {"memory above maximum", "max_memory: 1025MiB", false},
		{"one sensor", "sensors: [block_io]", true}, {"no sensors", "sensors: []", false}, {"unknown sensor", "sensors: [disk]", false}, {"duplicate sensor", "sensors: [tcp, tcp]", false},
		{"strict false", "strict: false", true}, {"strict true", "strict: true", true}, {"strict invalid type", "strict: yes", false},
		{"poll minimum", "poll_interval: 100ms", true}, {"poll below minimum", "poll_interval: 99ms", false}, {"poll maximum", "poll_interval: 1m", true}, {"poll above maximum", "poll_interval: 1m1s", false}, {"poll longer than history", "history: 1s\npoll_interval: 2s", false},
		{"timeout minimum", "timeout: 1s", true}, {"timeout below minimum", "timeout: 999ms", false}, {"timeout maximum", "timeout: 10m", true}, {"timeout above maximum", "timeout: 10m1s", false},
		{"block positive warn", nestedYAML("thresholds.block_io.warn", "1ns"), true}, {"block zero warn", nestedYAML("thresholds.block_io.warn", "0s"), false}, {"block critical greater", nestedYAML("thresholds.block_io.critical", "251ms"), true}, {"block critical equal", nestedYAML("thresholds.block_io.critical", "50ms"), false},
		{"scheduler positive warn", nestedYAML("thresholds.scheduler.warn", "1ns"), true}, {"scheduler zero warn", nestedYAML("thresholds.scheduler.warn", "0s"), false}, {"scheduler critical greater", nestedYAML("thresholds.scheduler.critical", "101ms"), true}, {"scheduler critical equal", nestedYAML("thresholds.scheduler.critical", "20ms"), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Load(writeSettingFile(t, test.yaml+"\n"), nil)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v error=%v\n%s", test.valid, err, test.yaml)
			}
		})
	}
}

func nestedYAML(key, value string) string {
	parts := strings.Split(key, ".")
	var out strings.Builder
	for i, part := range parts {
		out.WriteString(strings.Repeat("  ", i))
		out.WriteString(part)
		out.WriteString(":")
		if i == len(parts)-1 {
			out.WriteString(" ")
			out.WriteString(value)
		}
		out.WriteString("\n")
	}
	return out.String()
}

func writeSettingFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func schemaKeys(typ reflect.Type, prefix string) (all, leaves []string) {
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		key := field.Tag.Get("yaml")
		if key == "" || key == "-" {
			continue
		}
		if prefix != "" {
			key = prefix + "." + key
		}
		all = append(all, key)
		if field.Type.Kind() == reflect.Struct && field.Type != reflect.TypeFor[time.Duration]() {
			nestedAll, nestedLeaves := schemaKeys(field.Type, key)
			all = append(all, nestedAll...)
			leaves = append(leaves, nestedLeaves...)
		} else {
			leaves = append(leaves, key)
		}
	}
	return all, leaves
}
