//go:build linux && integration

package sensor

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestTCPResetTuplesWithAndWithoutSocket(t *testing.T) {
	cfg := config.Default()
	cfg.Enabled = []string{"tcp"}
	cfg.Strict, cfg.DetailRate = true, 4096
	ss, _, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ss[0].Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan model.Event, 1024)
	if err = ss[0].Start(ctx, func(e model.Event) {
		select {
		case events <- e:
		default:
		}
	}); err != nil {
		t.Fatal(err)
	}

	verifiedPairs := uint64(0)
	assertTuple := func(t *testing.T, src, dst *net.TCPAddr, sentSource, sentContext string) {
		t.Helper()
		sent, received := false, false
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		for !sent || !received {
			select {
			case e := <-events:
				if e.Type != "tcp_reset" || e.SourceIP != src.IP.String() || e.DestinationIP != dst.IP.String() || e.SourcePort != uint16(src.Port) || e.DestinationPort != uint16(dst.Port) {
					continue
				}
				if e.PID != 0 || e.TGID != 0 || e.Comm != "" {
					t.Fatalf("IRQ/current-task context was attributed as owner: %+v", e)
				}
				switch e.TCPDirection {
				case "sent":
					if e.EndpointSource != sentSource || e.SocketContext != sentContext {
						t.Fatalf("wrong sent reset provenance: %+v", e)
					}
					sent = true
				case "received":
					if e.EndpointSource != "socket" || e.SocketContext != "socket" {
						t.Fatalf("wrong received reset provenance: %+v", e)
					}
					received = true
				}
			case <-timer.C:
				t.Fatalf("reset %s → %s: sent=%v received=%v", src, dst, sent, received)
			}
		}
		verifiedPairs++
		t.Logf("%s → %s: sent(%s/%s) and received(socket) tuples verified", src, dst, sentSource, sentContext)
	}

	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network+"/no-listener", func(t *testing.T) {
			family, ip := unix.AF_INET, net.ParseIP("127.0.0.1")
			if network == "tcp6" {
				family, ip = unix.AF_INET6, net.ParseIP("::1")
			}
			// Bind without listen: reserve a private closed port, without a race
			// against another service taking a just-closed listener's port.
			fd, er := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if er != nil {
				t.Fatal(er)
			}
			defer unix.Close(fd)
			if family == unix.AF_INET {
				er = unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
			} else {
				er = unix.Bind(fd, &unix.SockaddrInet6{Addr: [16]byte{15: 1}})
			}
			if er != nil {
				t.Fatal(er)
			}
			addr, er := unix.Getsockname(fd)
			if er != nil {
				t.Fatal(er)
			}
			port := 0
			switch a := addr.(type) {
			case *unix.SockaddrInet4:
				port = a.Port
			case *unix.SockaddrInet6:
				port = a.Port
			}
			target := &net.TCPAddr{IP: ip, Port: port}
			reserve, er := net.ListenTCP(network, &net.TCPAddr{IP: ip})
			if er != nil {
				t.Fatal(er)
			}
			local := *reserve.Addr().(*net.TCPAddr)
			reserve.Close()
			dialer := net.Dialer{LocalAddr: &local, Timeout: time.Second}
			conn, er := dialer.DialContext(ctx, network, target.String())
			if conn != nil {
				conn.Close()
				t.Fatal("unexpected listener on private bound port")
			}
			if !errors.Is(er, syscall.ECONNREFUSED) {
				t.Fatalf("expected refused connection: %v", er)
			}
			assertTuple(t, target, &local, "packet_header", "none")
		})
		t.Run(network+"/abortive-close", func(t *testing.T) {
			ip := net.ParseIP("127.0.0.1")
			if network == "tcp6" {
				ip = net.ParseIP("::1")
			}
			listener, er := net.ListenTCP(network, &net.TCPAddr{IP: ip})
			if er != nil {
				t.Fatal(er)
			}
			defer listener.Close()
			client, er := net.DialTCP(network, nil, listener.Addr().(*net.TCPAddr))
			if er != nil {
				t.Fatal(er)
			}
			defer client.Close()
			server, er := listener.AcceptTCP()
			if er != nil {
				t.Fatal(er)
			}
			defer server.Close()
			src, dst := *client.LocalAddr().(*net.TCPAddr), *client.RemoteAddr().(*net.TCPAddr)
			if er = client.SetLinger(0); er != nil {
				t.Fatal(er)
			}
			client.Close()
			assertTuple(t, &src, &dst, "socket", "socket")
		})
	}
	m, err := ss[0].Snapshot(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if m.Resets < 2*verifiedPairs || m.Count != m.Resets+m.Retransmits {
		t.Fatalf("send/receive observations were not counted: %+v", m)
	}
}
