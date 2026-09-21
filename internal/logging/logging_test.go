package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLevelsAndIndependentLoggers(t *testing.T) {
	original := slog.Default()
	for _, tt := range []struct {
		level             string
		debug, info, warn bool
	}{
		{"debug", true, true, true}, {"info", false, true, true}, {"warn", false, false, true}, {"error", false, false, false},
	} {
		t.Run(tt.level, func(t *testing.T) {
			var out bytes.Buffer
			log := New(tt.level, &out)
			log.Debug("debug message")
			log.Info("info message")
			log.Warn("warn message")
			log.Error("error message")
			if strings.Contains(out.String(), "debug message") != tt.debug || strings.Contains(out.String(), "info message") != tt.info || strings.Contains(out.String(), "warn message") != tt.warn || !strings.Contains(out.String(), "error message") {
				t.Fatal("incorrect level filtering:", out.String())
			}
		})
	}
	if slog.Default() != original {
		t.Fatal("global logger changed")
	}
}
