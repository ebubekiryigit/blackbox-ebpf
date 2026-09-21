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

	"github.com/ebubekiryigit/blackbox-ebpf/internal/control"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestStatusReturnsFailureWhenNoSensorIsActive(t *testing.T) {
	dir, err := os.MkdirTemp("", "bbx-status-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "c.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		var request control.Request
		if err = json.NewDecoder(conn).Decode(&request); err == nil {
			err = json.NewEncoder(conn).Encode(control.Response{Version: model.ProtocolVersion, Health: &model.Health{Sensors: []model.SensorHealth{{Name: "scheduler", State: "error", Reason: "reader failed"}}}})
		}
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := New()
	cmd.SetContext(ctx)
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"status", "--socket", socket, "--color=never"})
	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "no active sensors") {
		t.Fatalf("unhealthy recorder returned success: %v", err)
	}
	if !strings.Contains(output.String(), "NO ACTIVE SENSORS") {
		t.Fatalf("status details were not rendered:\n%s", output.String())
	}
	if serverErr := <-done; serverErr != nil {
		t.Fatal(serverErr)
	}
}
