package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/app"
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

func shortSocket(t *testing.T) string {
	t.Helper()
	dir, e := os.MkdirTemp("", "bbx-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}
