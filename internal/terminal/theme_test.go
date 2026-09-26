package terminal

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestColorSelectionForRedirectedOutput(t *testing.T) {
	var b bytes.Buffer
	for _, mode := range []string{"auto", "never"} {
		if For(&b, mode).Color {
			t.Fatal("redirected output unexpectedly colored")
		}
	}
	t.Setenv("NO_COLOR", "1")
	if For(&b, "auto").Color || !For(&b, "always").Color {
		t.Fatal("explicit color mode must override auto environment detection")
	}
	if ValidMode("invalid") {
		t.Fatal("invalid color mode accepted")
	}
}
func TestPanelWrapsAndRemovesTerminalControls(t *testing.T) {
	var b bytes.Buffer
	Theme{Width: 40}.Panel(&b, Warning, strings.Repeat("title ", 20), "host\x1b[31m\n"+strings.Repeat("x", 100))
	for _, line := range strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n") {
		if n := utf8.RuneCountInString(line); n != 40 {
			t.Fatalf("panel width=%d: %q", n, line)
		}
	}
	if strings.Contains(b.String(), "\x1b") {
		t.Fatal("untrusted controls reached output")
	}
}

func TestTablesRemainReadableWithWideValuesAndUntrustedText(t *testing.T) {
	var narrow bytes.Buffer
	Theme{Width: 40}.Table(&narrow, "Sensor\tState\tEndpoint", []string{"TCP\thealthy\t172.17.0.2:32796 → 142.251.39.209:443", "block_io\terror\tbad\x1b[31m\nentry"}, []Tone{Good, Warning})
	for _, want := range []string{"Sensor: TCP", "State: healthy", "Endpoint:", "Sensor: block_io", "State: error"} {
		if !strings.Contains(narrow.String(), want) {
			t.Fatalf("narrow table lost %q:\n%s", want, narrow.String())
		}
	}
	if strings.Contains(narrow.String(), "\x1b") || strings.Contains(narrow.String(), "bad\nentry") {
		t.Fatalf("untrusted control reached table: %q", narrow.String())
	}
	for _, line := range strings.Split(strings.TrimSuffix(narrow.String(), "\n"), "\n") {
		if utf8.RuneCountInString(line) > 40 {
			t.Fatalf("narrow table exceeded terminal width: %q", line)
		}
	}
	var wide bytes.Buffer
	Theme{Color: true, Width: 100}.Table(&wide, "Sensor\tState", []string{"TCP\thealthy"}, []Tone{Good})
	if !strings.Contains(wide.String(), "\x1b[2m") || !strings.Contains(wide.String(), "\x1b[1;32m") || !strings.Contains(wide.String(), "TCP") {
		t.Fatalf("wide table lost alignment or color: %q", wide.String())
	}
}

func TestStatusFormattingKeepsCountsAndSensorNamesReadable(t *testing.T) {
	for _, tc := range []struct {
		count uint64
		want  string
	}{{0, "0"}, {999, "999"}, {1000, "1,000"}, {1234567890, "1,234,567,890"}} {
		if got := Count(tc.count); got != tc.want {
			t.Fatalf("Count(%d) = %q", tc.count, got)
		}
	}
	for _, tc := range []struct{ name, want string }{{"block_io", "Block I/O"}, {"scheduler", "Scheduler"}, {"tcp", "TCP"}, {"oom", "OOM"}, {"custom\nsource", "custom source"}} {
		if got := Sensor(tc.name); got != tc.want {
			t.Fatalf("Sensor(%q) = %q", tc.name, got)
		}
	}
	var out bytes.Buffer
	theme := Theme{Width: 40}
	theme.Section(&out, "COLLECTION NOTES")
	theme.Notice(&out, Warning, "I/O completions could not be timed", "No matching dispatch/start record was found.")
	if !strings.Contains(out.String(), "COLLECTION NOTES") || !strings.Contains(out.String(), "! I/O completions") || !strings.Contains(out.String(), "No matching dispatch/start") {
		t.Fatalf("coverage notice became unclear:\n%s", out.String())
	}
}
