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
