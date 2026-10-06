//go:build linux

package sensor

import (
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestBlockRequestTracepointLayouts(t *testing.T) {
	ctx := btf.FuncParam{Type: &btf.Pointer{Target: &btf.Void{}}}
	rq := btf.FuncParam{Type: &btf.Pointer{Target: &btf.Struct{Name: "request"}}}
	queue := btf.FuncParam{Type: &btf.Pointer{Target: &btf.Struct{Name: "request_queue"}}}
	for _, tc := range []struct {
		name    string
		params  []btf.FuncParam
		want    uint32
		invalid bool
	}{
		{"5.10 issue/requeue", []btf.FuncParam{ctx, queue, rq}, 1, false},
		{"modern issue/requeue", []btf.FuncParam{ctx, rq}, 0, false},
		{"missing request", []btf.FuncParam{ctx, queue}, 0, true},
		{"request in context slot", []btf.FuncParam{rq}, 0, true},
		{"unsupported position", []btf.FuncParam{ctx, queue, queue, rq}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := blockRequestIndexFromProto(&btf.FuncProto{Params: tc.params})
			if (err != nil) != tc.invalid || !tc.invalid && got != tc.want {
				t.Fatalf("index=%d, error=%v", got, err)
			}
		})
	}
}
