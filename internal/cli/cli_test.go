package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/app"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/capture"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/version"
)

func TestAnalyzeColorModesAndUnchangedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.bbx")
	if err := capture.WriteFile(path, app.Demo()); err != nil {
		t.Fatal(err)
	}
	execute := func(args ...string) (string, error) {
		cmd := New()
		var b bytes.Buffer
		cmd.SetOut(&b)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return b.String(), err
	}
	for _, mode := range []string{"auto", "never", "always"} {
		out, err := execute("analyze", path, "--color="+mode)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "\x1b[") != (mode == "always") {
			t.Fatalf("wrong color mode %s", mode)
		}
	}
	plain, err := execute("analyze", path, "--json", "--color=never")
	if err != nil {
		t.Fatal(err)
	}
	forced, err := execute("analyze", path, "--json", "--color=always")
	if err != nil || forced != plain || !json.Valid([]byte(forced)) {
		t.Fatal("color affected machine-readable output")
	}
	if _, err = execute("analyze", path, "--color=invalid"); err == nil {
		t.Fatal("invalid color mode accepted")
	}
}

func TestConfigCommandsUseMergedTypedSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("history: 2m\nmax_memory: 16MiB\nstrict: true\npoll_interval: 2s\n"), 0600); err != nil {
		t.Fatal(err)
	}
	execute := func(args ...string) (string, error) {
		cmd := New()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return out.String(), err
	}
	out, err := execute("config", "show", "--config", path, "--history", "3m", "--strict=false")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "history: 3m") || !strings.Contains(out, "max_memory: 16MiB") || !strings.Contains(out, "strict: false") {
		t.Fatalf("wrong effective config:\n%s", out)
	}
	if _, err = execute("config", "check", "--config", path); err != nil {
		t.Fatal(err)
	}
	if _, err = execute("config", "check", "--config", path, "--poll-interval=0s"); err == nil {
		t.Fatal("invalid flag accepted")
	}
	if _, err = execute("demo", "--config", path); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatal("offline command accepted a configuration file", err)
	}
}

func TestConfigShowRoundTripsEveryPublicSetting(t *testing.T) {
	input := filepath.Join(t.TempDir(), "input.yml")
	content := `log_level: debug
history: 2m
max_memory: 64MiB
sensors: [scheduler, oom]
strict: true
poll_interval: 2s
timeout: 45s
thresholds:
  block_io:
    warn: 60ms
    critical: 300ms
  scheduler:
    warn: 30ms
    critical: 150ms
auto_capture:
  enabled: false
  directory: /tmp/blackbox-auto
  sensors: [oom]
  before: 30s
  after: 0s
  max_files: 3
  max_storage: 64MiB
  write_timeout: 3m
`
	if err := os.WriteFile(input, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	want, err := config.Load(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	cmd := New()
	var shown bytes.Buffer
	cmd.SetOut(&shown)
	cmd.SetArgs([]string{"config", "show", "--config", input})
	if err = cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "shown.yml")
	if err = os.WriteFile(output, shown.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := config.Load(output, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("config show changed typed settings:\ngot  %+v\nwant %+v\n%s", got, want, shown.String())
	}
}
func TestOfflineWorkflowAndVersionContracts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "demo.bbx")
	cmd := New()
	var savedPath bytes.Buffer
	cmd.SetOut(&savedPath)
	cmd.SetArgs([]string{"demo", "-o", path})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if savedPath.String() != path+"\n" {
		t.Fatalf("demo stdout is not the saved path: %q", savedPath.String())
	}
	cmd = New()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"analyze", path, "--color=never"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Synthetic demonstration") || !strings.Contains(out.String(), "demo-database") {
		t.Fatal("offline demo workflow failed")
	}
	cmd = New()
	out.Reset()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if out.String() != "Blackbox "+version.String()+"\n" {
		t.Fatalf("unexpected version output %q", out.String())
	}
}
