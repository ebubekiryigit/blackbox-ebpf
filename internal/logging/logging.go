// Package logging creates per-run loggers without changing global slog state.
package logging

import (
	"io"
	"log/slog"
)

func New(level string, output io.Writer) *slog.Logger {
	severity := slog.LevelInfo
	switch level {
	case "debug":
		severity = slog.LevelDebug
	case "warn":
		severity = slog.LevelWarn
	case "error":
		severity = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(output, &slog.HandlerOptions{Level: severity}))
}
