//go:build linux

package sensor

import "testing"

func TestTCPDirectionProvenanceAndLegacyNormalization(t *testing.T) {
	base := wireEvent{Kind: 4, Family: 2, SourcePort: 40000, DestinationPort: 443}
	copy(base.SourceIP[:], []byte{127, 0, 0, 1})
	copy(base.DestinationIP[:], []byte{192, 0, 2, 1})
	legacy := normalize(base)
	if legacy.Type != "tcp_reset" || legacy.TCPDirection != "" || legacy.SocketContext != "" || legacy.EndpointSource != "" || legacy.SourcePort != 40000 {
		t.Fatalf("legacy reset was reinterpreted: %+v", legacy)
	}
	received := base
	received.Kind, received.Operation = 6, 8|4|1
	e := normalize(received)
	if e.Type != "tcp_reset" || e.TCPDirection != "received" || e.SocketContext != "socket" || e.EndpointSource != "socket" || e.SourceIP != "192.0.2.1" || e.SourcePort != 443 || e.DestinationPort != 40000 {
		t.Fatalf("received packet tuple is reversed: %+v", e)
	}
	packet := base
	packet.Operation = 8 | 2
	e = normalize(packet)
	if e.TCPDirection != "sent" || e.SocketContext != "none" || e.EndpointSource != "packet_header" || e.SourcePort != 40000 || e.PID != 0 || e.TGID != 0 || e.Comm != "" {
		t.Fatalf("socket-less provenance or ownership is incorrect: %+v", e)
	}
	e = normalize(wireEvent{Kind: 4, Operation: 8})
	if e.EndpointSource != "unavailable" || e.SourceIP != "" || e.DestinationIP != "" {
		t.Fatal("absent endpoints became a fabricated tuple")
	}
}
