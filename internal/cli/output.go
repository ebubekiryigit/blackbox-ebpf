package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/control"
)

func automaticOutputPath(kind string, now time.Time, entropy io.Reader) (string, error) {
	var suffix [3]byte
	if _, err := io.ReadFull(entropy, suffix[:]); err != nil {
		return "", fmt.Errorf("generate %s filename: %w", kind, err)
	}
	name := fmt.Sprintf("blackbox-%s-%s-%s.bbx", kind, now.UTC().Format("20060102T150405Z"), hex.EncodeToString(suffix[:]))
	path, err := filepath.Abs(name)
	if err != nil {
		return "", fmt.Errorf("resolve %s destination: %w", kind, err)
	}
	return path, nil
}

func newOutputPath(kind string) (string, error) {
	return automaticOutputPath(kind, time.Now(), rand.Reader)
}

func ensureNoDaemon(ctx context.Context, c config.Config) error {
	if _, err := control.CallWithOptions(ctx, c.Socket, control.Request{Operation: "status"}, nil, c.Control); err == nil {
		return fmt.Errorf("daemon is already recording at %s; use blackbox snapshot instead", c.Socket)
	} else if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
		return nil
	} else {
		return fmt.Errorf("check for an existing daemon at %s: %w", c.Socket, err)
	}
}
