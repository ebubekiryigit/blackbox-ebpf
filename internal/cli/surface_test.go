package cli

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func TestOfflineHelpAndCommandsHideCollectorTuning(t *testing.T) {
	for _, command := range [][]string{{"--help"}, {"analyze", "--help"}, {"status", "--help"}, {"snapshot", "--help"}} {
		cmd := New()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs(command)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		for _, removed := range []string{"--resources-", "--capture-max-", "--control-max-", "--report-", "--detail-rate", "--block-io-warn", "--history"} {
			if strings.Contains(out.String(), removed) {
				t.Fatalf("unrelated tuning in %v: %s", command, removed)
			}
		}
	}
	for _, command := range [][]string{{"--help"}, {"analyze", "--help"}, {"status", "--help"}, {"snapshot", "--help"}, {"demo", "--help"}} {
		cmd := New()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs(command)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "--config") {
			t.Fatalf("configuration file exposed by %v: %s", command, out.String())
		}
	}
	for _, command := range [][]string{{"daemon", "--help"}, {"capture", "--help"}, {"config", "check", "--help"}, {"config", "show", "--help"}} {
		cmd := New()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs(command)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "--config") {
			t.Fatalf("configuration file missing from %v: %s", command, out.String())
		}
	}
	cmd := New()
	var captureHelp bytes.Buffer
	cmd.SetOut(&captureHelp)
	cmd.SetArgs([]string{"capture", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(captureHelp.String(), "--history") || !strings.Contains(captureHelp.String(), "--duration") {
		t.Fatal("capture exposes conflicting recording windows")
	}
	cmd = New()
	cmd.SetArgs([]string{"config", "check", "--resources-ring-bytes", "65536"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("internal knob remains an accepted flag")
	}
	cmd = New()
	cmd.SetArgs([]string{"capture", "--history", "1m"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatal("capture accepted an ignored history override", err)
	}
}

func TestCommandConfigSurfacesStayScoped(t *testing.T) {
	tests := []struct {
		path []string
		keys []string
	}{
		{[]string{"daemon"}, []string{"history", "log_level", "max_memory", "poll_interval", "sensors", "socket", "strict", "thresholds.block_io.critical", "thresholds.block_io.warn", "thresholds.scheduler.critical", "thresholds.scheduler.warn", "timeout"}},
		{[]string{"capture"}, []string{"log_level", "max_memory", "poll_interval", "sensors", "strict", "thresholds.block_io.critical", "thresholds.block_io.warn", "thresholds.scheduler.critical", "thresholds.scheduler.warn"}},
		{[]string{"status"}, []string{"socket", "timeout"}},
		{[]string{"snapshot"}, []string{"socket", "timeout"}},
		{[]string{"analyze"}, nil},
		{[]string{"config", "check"}, []string{"history", "log_level", "max_memory", "poll_interval", "sensors", "strict", "thresholds.block_io.critical", "thresholds.block_io.warn", "thresholds.scheduler.critical", "thresholds.scheduler.warn", "timeout"}},
		{[]string{"config", "show"}, []string{"history", "log_level", "max_memory", "poll_interval", "sensors", "strict", "thresholds.block_io.critical", "thresholds.block_io.warn", "thresholds.scheduler.critical", "thresholds.scheduler.warn", "timeout"}},
	}
	for _, test := range tests {
		t.Run(strings.Join(test.path, " "), func(t *testing.T) {
			command := findCommand(t, New(), test.path)
			var got []string
			command.Flags().VisitAll(func(flag *pflag.Flag) {
				if keys := flag.Annotations[config.FlagKey]; len(keys) == 1 {
					got = append(got, keys[0])
				}
			})
			slices.Sort(got)
			want := append([]string(nil), test.keys...)
			slices.Sort(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("config surface = %v, want %v", got, want)
			}
		})
	}
}

func findCommand(t *testing.T, root *cobra.Command, path []string) *cobra.Command {
	t.Helper()
	command, remaining, err := root.Find(path)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("find %v: command=%v remaining=%v err=%v", path, command, remaining, err)
	}
	return command
}
