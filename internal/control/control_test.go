package control

import (
	"bytes"
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
	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestBusySocketCannotBeReplaced(t *testing.T) {
	path := shortSocket(t)
	l, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	if e = Serve(context.Background(), path, &app.Engine{}); e == nil {
		t.Fatal("live socket replaced")
	}
	conn, e := net.Dial("unix", path)
	if e != nil {
		t.Fatal("original daemon socket removed")
	}
	conn.Close()
}
func TestClientKeepsCaptureBytesBufferedAfterHeader(t *testing.T) {
	path := shortSocket(t)
	listener, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	payload := []byte("captured bytes arriving in the same socket write as the JSON response")
	done := make(chan error, 1)
	go func() {
		conn, er := listener.Accept()
		if er != nil {
			done <- er
			return
		}
		defer conn.Close()
		var req Request
		if er = json.NewDecoder(conn).Decode(&req); er != nil {
			done <- er
			return
		}
		header, _ := json.Marshal(Response{Version: model.ProtocolVersion, Capture: true})
		_, er = conn.Write(append(append(header, '\n'), payload...))
		done <- er
	}()
	var out bytes.Buffer
	if _, e = Call(context.Background(), path, Request{Operation: "snapshot", LastNS: 1}, &out); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("buffered capture bytes lost: %q", out.Bytes())
	}
}

func TestServerRejectsInvalidRequestsWithVersionedErrors(t *testing.T) {
	limits := config.Default().Control
	for _, tc := range []struct{ name, request, want string }{
		{"oversized request", strings.Repeat("x", limits.RequestBytes) + "\n", "invalid control request"},
		{"malformed JSON", "{\n", "unexpected end of JSON input"},
		{"incompatible protocol", fmt.Sprintf("{\"version\":%d,\"operation\":\"status\"}\n", model.ProtocolVersion+1), "unsupported control protocol"},
		{"unknown operation", fmt.Sprintf("{\"version\":%d,\"operation\":\"remove\"}\n", model.ProtocolVersion), "unknown operation"},
		{"snapshot without duration", fmt.Sprintf("{\"version\":%d,\"operation\":\"snapshot\"}\n", model.ProtocolVersion), "last must be positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			defer clientConn.Close()
			listener := &singleConnListener{conn: serverConn, closed: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- serveListener(ctx, listener, &app.Engine{Config: config.Default()}, limits) }()
			if err := clientConn.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(clientConn, tc.request); err != nil {
				t.Fatal(err)
			}
			var response Response
			if err := json.NewDecoder(clientConn).Decode(&response); err != nil {
				t.Fatal(err)
			}
			if response.Version != model.ProtocolVersion || !strings.Contains(response.Error, tc.want) {
				t.Fatalf("request error was not actionable: %+v", response)
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestServerLimitsResponseHeaderSize(t *testing.T) {
	limits := config.Default().Control
	limits.ResponseBytes = 512
	var output bytes.Buffer
	if err := writeResponse(&output, limits, Response{Error: strings.Repeat("x", limits.ResponseBytes)}); err == nil {
		t.Fatal("oversized server response was accepted")
	}
	var response Response
	if err := json.Unmarshal(output.Bytes(), &response); err != nil || response.Version != model.ProtocolVersion || response.Error != "control response exceeds configured header limit" {
		t.Fatalf("oversized response was not bounded and explained: %v %+v", err, response)
	}
}

func shortSocket(t *testing.T) string {
	t.Helper()
	dir, e := os.MkdirTemp("", "bbx-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}
