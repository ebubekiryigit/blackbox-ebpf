package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/app"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/capture"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/control"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestSnapshotDefaultFollowsDaemonHistoryAndExplicitLastSkipsDiscovery(t *testing.T) {
	for _, variant := range []string{"daemon history", "explicit last", "legacy daemon"} {
		t.Run(variant, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "bbx-cli-")
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
			want := 90 * time.Second
			connections := 2
			args := []string{"snapshot", "--socket", socket, "-o", filepath.Join(t.TempDir(), "incident.bbx")}
			switch variant {
			case "explicit last":
				connections = 1
				want = 10 * time.Second
				args = append(args, "--last=10s")
			case "legacy daemon":
				want = config.Default().History
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
			defer stop()
			go func() {
				for i := 0; i < connections; i++ {
					conn, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					var req control.Request
					err = json.NewDecoder(conn).Decode(&req)
					if err != nil {
						conn.Close()
						done <- err
						return
					}
					response := control.Response{Version: model.ProtocolVersion}
					if req.Operation == "status" {
						if i != 0 || connections != 2 {
							conn.Close()
							done <- io.ErrUnexpectedEOF
							return
						}
						if variant != "legacy daemon" {
							response.Settings = &model.RecordingSettings{HistoryNS: uint64(90 * time.Second)}
						}
						err = json.NewEncoder(conn).Encode(response)
					} else {
						if req.Operation != "snapshot" || req.LastNS != int64(want) {
							conn.Close()
							done <- io.ErrUnexpectedEOF
							return
						}
						response.Capture = true
						err = json.NewEncoder(conn).Encode(response)
						if err == nil {
							err = (capture.Container{}).Write(conn, app.Demo())
						}
					}
					conn.Close()
					if err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			cmd := New()
			cmd.SetContext(ctx)
			cmd.SetOut(io.Discard)
			cmd.SetArgs(args)
			if err = cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal("snapshot requested wrong history or extra RPC", err)
			}
		})
	}
}

func TestSnapshotRejectsIncompleteStreamWithoutPublishing(t *testing.T) {
	dir, err := os.MkdirTemp("", "bbx-cli-")
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
			err = json.NewEncoder(conn).Encode(control.Response{Version: model.ProtocolVersion, Capture: true})
		}
		if err == nil {
			_, err = conn.Write([]byte("truncated capture"))
		}
		done <- err
	}()

	destination := filepath.Join(t.TempDir(), "incident.bbx")
	cmd := New()
	cmd.SetArgs([]string{"snapshot", "--socket", socket, "--last=1s", "-o", destination})
	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "snapshot failed") || !strings.Contains(err.Error(), "validate capture before publication") {
		t.Fatalf("incomplete stream was opaque or accepted: %v", err)
	}
	if _, statErr := os.Stat(destination); !os.IsNotExist(statErr) {
		t.Fatalf("incomplete capture was published: %v", statErr)
	}
	if serverErr := <-done; serverErr != nil {
		t.Fatal(serverErr)
	}
}

func TestSnapshotGeneratesDestinationInCurrentDirectory(t *testing.T) {
	dir, err := os.MkdirTemp("", "bbx-cli-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	t.Chdir(dir)
	socket := filepath.Join(dir, "c.sock")
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
		if acceptErr = json.NewDecoder(conn).Decode(&request); acceptErr == nil && (request.Operation != "snapshot" || request.LastNS != int64(time.Second)) {
			acceptErr = fmt.Errorf("unexpected request: %+v", request)
		}
		if acceptErr == nil {
			acceptErr = json.NewEncoder(conn).Encode(control.Response{Version: model.ProtocolVersion, Capture: true})
		}
		if acceptErr == nil {
			acceptErr = (capture.Container{}).Write(conn, app.Demo())
		}
		done <- acceptErr
	}()

	var out strings.Builder
	cmd := New()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"snapshot", "--socket", socket, "--last=1s"})
	if err = cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	path := strings.TrimSpace(out.String())
	if !filepath.IsAbs(path) || filepath.Dir(path) != dir || !strings.HasPrefix(filepath.Base(path), "blackbox-snapshot-") {
		t.Fatalf("unexpected generated destination %q", path)
	}
	if _, err = capture.ReadFile(path); err != nil {
		t.Fatalf("generated snapshot is not readable: %v", err)
	}
}
