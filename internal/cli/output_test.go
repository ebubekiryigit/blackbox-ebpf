package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/control"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestAutomaticCapturePathIsAbsoluteSortableAndDistinct(t *testing.T) {
	now := time.Date(2026, 9, 21, 14, 38, 12, 999, time.FixedZone("test", 3*60*60))
	first, err := automaticOutputPath("capture", now, bytes.NewReader([]byte{0x7f, 0x3a, 0x91}))
	if err != nil {
		t.Fatal(err)
	}
	second, err := automaticOutputPath("capture", now, bytes.NewReader([]byte{0x00, 0x00, 0x01}))
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(first) || filepath.Base(first) != "blackbox-capture-20260921T113812Z-7f3a91.bbx" || first == second {
		t.Fatalf("unexpected generated paths %q and %q", first, second)
	}
	snapshot, err := automaticOutputPath("snapshot", now, bytes.NewReader([]byte{0x12, 0x34, 0x56}))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(snapshot) != "blackbox-snapshot-20260921T113812Z-123456.bbx" {
		t.Fatalf("unexpected generated snapshot path %q", snapshot)
	}
}

func TestSavedOutputIsOnlyAnAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	var out bytes.Buffer
	if err := saved(&out, "incident.bbx", nil); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "incident.bbx") + "\n"
	if out.String() != want {
		t.Fatalf("stdout is not pipeable: got %q want %q", out.String(), want)
	}
}

func TestStandaloneCaptureDetectsRunningDaemon(t *testing.T) {
	dir, err := os.MkdirTemp("", "bbx-capture-guard-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer conn.Close()
		var request control.Request
		if acceptErr = json.NewDecoder(conn).Decode(&request); acceptErr == nil {
			acceptErr = json.NewEncoder(conn).Encode(control.Response{Version: model.ProtocolVersion, Health: &model.Health{}})
		}
		done <- acceptErr
	}()
	c := config.Default()
	c.Socket = socket
	err = ensureNoDaemon(context.Background(), c)
	if err == nil || !strings.Contains(err.Error(), "use blackbox snapshot") {
		t.Fatalf("running daemon was not rejected: %v", err)
	}
	if serverErr := <-done; serverErr != nil {
		t.Fatal(serverErr)
	}
	c.Socket = filepath.Join(dir, "absent.sock")
	if err = ensureNoDaemon(context.Background(), c); err != nil {
		t.Fatalf("absent daemon rejected standalone capture: %v", err)
	}
}
