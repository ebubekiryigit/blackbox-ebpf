//go:build linux && integration

package sensor

import (
	"context"
	"encoding/binary"
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
	resetCoverage := ss[0].Health().TCPResetCoverage
	if resetCoverage == "" {
		t.Fatal("TCP reset capability was not recorded in sensor health")
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
		if network == "tcp6" {
			probe, probeErr := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1")})
			if probeErr != nil {
				t.Run("tcp6", func(t *testing.T) { t.Skipf("IPv6 loopback is unavailable: %v", probeErr) })
				continue
			}
			probe.Close()
		}
		t.Run(network+"/no-listener", func(t *testing.T) {
			if resetCoverage != model.TCPResetCoverageSupported {
				t.Skipf("socketless sent resets are not confirmed by kernel BTF: %s", resetCoverage)
			}
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
		t.Run(network+"/listener-stray-ack", func(t *testing.T) {
			ip, rawNetwork := net.ParseIP("127.0.0.1"), "ip4:tcp"
			if network == "tcp6" {
				ip, rawNetwork = net.ParseIP("::1"), "ip6:tcp"
			}
			listener, er := net.ListenTCP(network, &net.TCPAddr{IP: ip})
			if er != nil {
				t.Fatal(er)
			}
			defer listener.Close()
			// Reserve the source port too; this ACK is not part of a connection.
			source, er := net.ListenTCP(network, &net.TCPAddr{IP: ip})
			if er != nil {
				t.Fatal(er)
			}
			defer source.Close()
			src, dst := source.Addr().(*net.TCPAddr), listener.Addr().(*net.TCPAddr)
			raw, er := net.DialIP(rawNetwork, &net.IPAddr{IP: ip}, &net.IPAddr{IP: ip})
			if er != nil {
				t.Fatal(er)
			}
			defer raw.Close()
			if _, er = raw.Write(strayACK(src, dst)); er != nil {
				t.Fatal(er)
			}
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			for {
				select {
				case e := <-events:
					if e.Type != "tcp_reset" || e.TCPDirection != "sent" || e.SourcePort != uint16(dst.Port) || e.DestinationPort != uint16(src.Port) {
						continue
					}
					if e.SourceIP != dst.IP.String() || e.DestinationIP != src.IP.String() || e.State != 10 || e.EndpointSource != "packet_header" || e.SocketContext != "socket" || e.PID != 0 || e.TGID != 0 || e.Comm != "" {
						t.Fatalf("listener reset lost its packet peer or provenance: %+v", e)
					}
					t.Logf("listener reset tuple verified: %+v", e)
					return
				case <-timer.C:
					t.Fatalf("no listener reset for stray ACK %s → %s", src, dst)
				}
			}
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

// TCP header plus checksum for a raw loopback ACK. No packet payload is sent.
func strayACK(src, dst *net.TCPAddr) []byte {
	packet := make([]byte, 20)
	binary.BigEndian.PutUint16(packet[0:2], uint16(src.Port))
	binary.BigEndian.PutUint16(packet[2:4], uint16(dst.Port))
	binary.BigEndian.PutUint32(packet[8:12], 1)
	packet[12], packet[13] = 5<<4, 0x10
	var pseudo []byte
	if ip := src.IP.To4(); ip != nil {
		pseudo = append(pseudo, ip...)
		pseudo = append(pseudo, dst.IP.To4()...)
		pseudo = append(pseudo, 0, 6, 0, byte(len(packet)))
	} else {
		pseudo = append(pseudo, src.IP.To16()...)
		pseudo = append(pseudo, dst.IP.To16()...)
		pseudo = append(pseudo, 0, 0, 0, byte(len(packet)), 0, 0, 0, 6)
	}
	sum := uint32(0)
	for _, b := range [][]byte{pseudo, packet} {
		for i := 0; i < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(packet[16:18], ^uint16(sum))
	return packet
}
