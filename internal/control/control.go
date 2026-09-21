// Package control implements a small versioned protocol over a private Unix socket.
package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/app"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/capture"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

type Request struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
	LastNS    int64  `json:"last_ns,omitempty"`
}
type Response struct {
	Version  int                      `json:"version"`
	Error    string                   `json:"error,omitempty"`
	Health   *model.Health            `json:"health,omitempty"`
	Capture  bool                     `json:"capture,omitempty"`
	Settings *model.RecordingSettings `json:"settings,omitempty"`
}

func Serve(ctx context.Context, path string, e *app.Engine) error {
	limits := e.Config.Control
	// Empty engine values are useful in socket-ownership tests.
	if limits == (config.Control{}) {
		limits = config.Default().Control
	}
	if err := limits.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := privateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("control path exists and is not a socket")
		}
		c, er := net.DialTimeout("unix", path, limits.DialTimeout)
		if er == nil {
			c.Close()
			return fmt.Errorf("daemon already listening on %s", path)
		}
		if !errors.Is(er, syscall.ECONNREFUSED) {
			return fmt.Errorf("refuse to replace socket: %w", er)
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer l.Close()
	defer os.Remove(path)
	if err = os.Chmod(path, 0600); err != nil {
		return err
	}
	return serveListener(ctx, l, e, limits)
}

func serveListener(ctx context.Context, l net.Listener, e *app.Engine, limits config.Control) error {
	stopListener := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stopListener()
	var wg sync.WaitGroup
	defer wg.Wait()
	clients := make(chan struct{}, limits.MaxClients)
	snapshot := make(chan struct{}, 1)
	var retryDelay time.Duration
	for {
		conn, er := l.Accept()
		if er != nil {
			if ctx.Err() != nil {
				return nil
			}
			if netErr, ok := er.(net.Error); ok && netErr.Temporary() {
				if retryDelay == 0 {
					retryDelay = 5 * time.Millisecond
				} else {
					retryDelay = min(2*retryDelay, time.Second)
				}
				timer := time.NewTimer(retryDelay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
				}
				continue
			}
			return er
		}
		retryDelay = 0
		select {
		case clients <- struct{}{}:
		default:
			_ = conn.SetWriteDeadline(time.Now().Add(min(limits.DialTimeout, time.Second)))
			_ = writeResponse(conn, limits, Response{Error: "control server is busy; retry later"})
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-clients }()
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stop()
			_ = conn.SetDeadline(time.Now().Add(limits.Timeout))
			respond := func(r Response) error { return writeResponse(conn, limits, r) }
			line, er := bufio.NewReader(io.LimitReader(conn, int64(limits.RequestBytes)+1)).ReadBytes('\n')
			if er != nil || len(line) > limits.RequestBytes {
				respond(Response{Error: "invalid control request"})
				return
			}
			var req Request
			if er = json.Unmarshal(line, &req); er != nil {
				respond(Response{Error: er.Error()})
				return
			}
			if req.Version != model.ProtocolVersion {
				respond(Response{Error: "unsupported control protocol"})
				return
			}
			if req.Operation != "status" && req.Operation != "snapshot" {
				respond(Response{Error: "unknown operation"})
				return
			}
			if req.Operation == "snapshot" {
				if req.LastNS <= 0 {
					respond(Response{Error: "last must be positive"})
					return
				}
				select {
				case snapshot <- struct{}{}:
					defer func() { <-snapshot }()
				default:
					respond(Response{Error: "a snapshot is already being written"})
					return
				}
			}
			queryCtx, cancel := context.WithTimeout(ctx, limits.QueryTimeout)
			defer cancel()
			last := time.Duration(0)
			if req.Operation == "snapshot" {
				last = time.Duration(req.LastNS)
			}
			result, er := e.Ask(queryCtx, last)
			if er != nil {
				respond(Response{Error: er.Error()})
				return
			}
			settings := e.Settings()
			if er = respond(Response{Health: &result.Health, Settings: &settings, Capture: req.Operation == "snapshot"}); er != nil {
				return
			}
			if req.Operation == "snapshot" {
				if er = (capture.Container{Limits: e.Config.Capture}).Write(&boundedWriter{Writer: conn, remaining: limits.MaxCaptureBytes}, result.Capture); er != nil {
					e.RecordSnapshotFailure(er)
				}
			}
		}()
	}
}

func writeResponse(dst io.Writer, limits config.Control, response Response) error {
	response.Version = model.ProtocolVersion
	b, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if len(b)+1 > limits.ResponseBytes {
		b, _ = json.Marshal(Response{Version: model.ProtocolVersion, Error: "control response exceeds configured header limit"})
		if _, err = dst.Write(append(b, '\n')); err != nil {
			return err
		}
		return fmt.Errorf("response header budget exceeded")
	}
	_, err = dst.Write(append(b, '\n'))
	return err
}

func Call(ctx context.Context, path string, req Request, dst io.Writer) (Response, error) {
	return CallWithOptions(ctx, path, req, dst, config.Default().Control)
}
func CallWithOptions(ctx context.Context, path string, req Request, dst io.Writer, limits config.Control) (Response, error) {
	var response Response
	if err := limits.Validate(); err != nil {
		return response, err
	}
	conn, err := (&net.Dialer{Timeout: limits.DialTimeout}).DialContext(ctx, "unix", path)
	if err != nil {
		return response, fmt.Errorf("connect daemon at %s: %w", path, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(limits.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	req.Version = model.ProtocolVersion
	if err = json.NewEncoder(conn).Encode(req); err != nil {
		return response, err
	}
	reader := bufio.NewReaderSize(conn, limits.ResponseBytes)
	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return response, fmt.Errorf("oversized control response")
	}
	if err != nil {
		return response, err
	}
	if len(line) > limits.ResponseBytes {
		return response, fmt.Errorf("oversized control response")
	}
	if err = json.Unmarshal(line, &response); err != nil {
		return response, err
	}
	if response.Version != model.ProtocolVersion {
		return response, fmt.Errorf("unsupported control protocol %d (client supports %d); use matching client and daemon versions", response.Version, model.ProtocolVersion)
	}
	if response.Error != "" {
		return response, fmt.Errorf("%s", response.Error)
	}
	if response.Capture {
		if dst == nil {
			return response, fmt.Errorf("capture destination required")
		}
		n, copyErr := io.Copy(dst, io.LimitReader(reader, limits.MaxCaptureBytes+1))
		err = copyErr
		if n > limits.MaxCaptureBytes {
			return response, fmt.Errorf("capture exceeds configured transport limit")
		}
		if err != nil {
			return response, err
		}
	}
	return response, nil
}

// boundedWriter enforces the server's encoded transport budget as well as the
// client's independently configured read budget. A partial stream never publishes.
type boundedWriter struct {
	io.Writer
	remaining int64
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, fmt.Errorf("capture exceeds configured transport limit")
	}
	n, err := w.Writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}
