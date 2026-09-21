package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/app"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestClientRejectsIncompatibleProtocolAndTransportOverflow(t *testing.T) {
	for _, variant := range []string{"protocol", "capture limit", "header limit"} {
		t.Run(variant, func(t *testing.T) {
			path := shortSocket(t)
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			limits := config.Default().Control
			limits.MaxCaptureBytes = config.MinMemory
			limits.ResponseBytes = 512
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				var req Request
				if json.NewDecoder(conn).Decode(&req) != nil {
					return
				}
				response := Response{Version: model.ProtocolVersion}
				payload := ""
				switch variant {
				case "protocol":
					response.Version++
				case "capture limit":
					response.Capture = true
					payload = strings.Repeat("x", int(limits.MaxCaptureBytes)+1)
				case "header limit":
					response.Error = strings.Repeat("x", limits.ResponseBytes+1)
				}
				json.NewEncoder(conn).Encode(response)
				conn.Write([]byte(payload))
			}()
			var out bytes.Buffer
			_, err = CallWithOptions(context.Background(), path, Request{Operation: "snapshot", LastNS: 1}, &out, limits)
			if err == nil {
				t.Fatal("invalid response accepted")
			}
			<-done
			if variant == "protocol" && !strings.Contains(err.Error(), "matching client and daemon") {
				t.Fatal("unhelpful upgrade error", err)
			}
			if int64(out.Len()) > limits.MaxCaptureBytes+1 {
				t.Fatal("unbounded capture transport")
			}
		})
	}
}
func TestDaemonShutdownClosesIdleControlClients(t *testing.T) {
	path := shortSocket(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &app.Engine{Config: config.Default()}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, path, e) }()
	var conn net.Conn
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.Dial("unix", path)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The idle client sends no header. Cancellation must not wait for its timeout.
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for an idle client")
	}
}

func TestBusyControlServerReturnsExplicitError(t *testing.T) {
	path := shortSocket(t)
	limits := config.Default().Control
	limits.MaxClients = 1
	limits.Timeout = time.Second
	limits.QueryTimeout = 100 * time.Millisecond
	limits.DialTimeout = 100 * time.Millisecond
	cfg := config.Default()
	cfg.Control = limits
	e := &app.Engine{Config: cfg}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, path, e) }()

	var first net.Conn
	var err error
	deadline := time.Now().Add(time.Second)
	for first == nil && time.Now().Before(deadline) {
		first, err = net.DialTimeout("unix", path, 50*time.Millisecond)
		if err != nil {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if first == nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err = first.Write([]byte("{")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)

	var busy error
	for time.Now().Before(deadline) {
		_, busy = CallWithOptions(context.Background(), path, Request{Operation: "status"}, nil, limits)
		if busy != nil && strings.Contains(busy.Error(), "control server is busy") {
			break
		}
	}
	if busy == nil || !strings.Contains(busy.Error(), "control server is busy") {
		t.Fatalf("overload remained opaque: %v", busy)
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "temporary accept failure" }
func (temporaryAcceptError) Timeout() bool   { return false }
func (temporaryAcceptError) Temporary() bool { return true }

type retryListener struct {
	calls     atomic.Int32
	closed    chan struct{}
	closeOnce sync.Once
}

func (l *retryListener) Accept() (net.Conn, error) {
	if l.calls.Add(1) == 1 {
		return nil, temporaryAcceptError{}
	}
	<-l.closed
	return nil, net.ErrClosed
}
func (l *retryListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}
func (*retryListener) Addr() net.Addr { return controlTestAddr("retry") }

type controlTestAddr string

func (a controlTestAddr) Network() string { return "test" }
func (a controlTestAddr) String() string  { return string(a) }

func TestTemporaryAcceptFailureDoesNotStopServer(t *testing.T) {
	listener := &retryListener{closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveListener(ctx, listener, &app.Engine{Config: config.Default()}, config.Default().Control)
	}()
	deadline := time.Now().Add(time.Second)
	for listener.calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if listener.calls.Load() < 2 {
		t.Fatal("temporary accept error was not retried")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
