//go:build linux

package sensor

import (
	"testing"

	"github.com/cilium/ebpf/btf"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestTCPResetCoverageFromTracepointBTF(t *testing.T) {
	ptr := &btf.Pointer{Target: &btf.Int{Name: "socket", Size: 8}}
	for _, tc := range []struct {
		name   string
		params []btf.FuncParam
		want   string
	}{
		{"older signature", []btf.FuncParam{{Type: ptr}, {Type: ptr}, {Type: ptr}}, model.TCPResetCoverageLimited},
		{"reason argument", []btf.FuncParam{{Type: ptr}, {Type: ptr}, {Type: ptr}, {Type: &btf.Enum{Name: "sk_rst_reason", Size: 4}}}, model.TCPResetCoverageSupported},
		{"unexpected argument", []btf.FuncParam{{Type: ptr}, {Type: ptr}, {Type: ptr}, {Type: ptr}}, model.TCPResetCoverageUnknown},
		{"incomplete signature", []btf.FuncParam{{Type: ptr}}, model.TCPResetCoverageUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tcpResetCoverageFromProto(&btf.FuncProto{Params: tc.params})
			if got != tc.want {
				t.Fatalf("coverage=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestTCPRetransmitErrorArgumentFromBTF(t *testing.T) {
	ptr := &btf.Pointer{Target: &btf.Int{Name: "socket", Size: 8}}
	for _, tc := range []struct {
		name   string
		params []btf.FuncParam
		want   uint32
		fails  bool
	}{
		{"older signature", []btf.FuncParam{{Type: ptr}, {Type: ptr}, {Type: ptr}}, 0, false},
		{"error argument", []btf.FuncParam{{Type: ptr}, {Type: ptr}, {Type: ptr}, {Type: &btf.Int{Name: "err", Size: 4}}}, 1, false},
		{"unknown argument", []btf.FuncParam{{Type: ptr}, {Type: ptr}, {Type: ptr}, {Type: ptr}}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tcpRetransmitHasErrorArgFromProto(&btf.FuncProto{Params: tc.params})
			if got != tc.want || (err != nil) != tc.fails {
				t.Fatalf("error argument=%d, err=%v", got, err)
			}
		})
	}
}
