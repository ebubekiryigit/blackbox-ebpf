//go:build linux

package sensor

import (
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestOOMVictimArgumentLayouts(t *testing.T) {
	for _, test := range []struct {
		name    string
		arg     btf.Type
		want    uint32
		wantErr bool
	}{
		{"legacy PID", &btf.Int{Name: "int", Size: 4}, 0, false},
		{"task pointer", &btf.Pointer{Target: &btf.Struct{Name: "task_struct"}}, 1, false},
		{"unexpected pointer", &btf.Pointer{Target: &btf.Struct{Name: "other"}}, 0, true},
		{"unexpected integer", &btf.Int{Name: "long", Size: 8}, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			proto := &btf.FuncProto{Params: []btf.FuncParam{{Name: "data", Type: &btf.Pointer{Target: &btf.Void{}}}, {Name: "victim", Type: test.arg}}}
			got, err := oomVictimTaskArgFromProto(proto)
			if got != test.want || (err != nil) != test.wantErr {
				t.Fatalf("argument layout: task=%d err=%v", got, err)
			}
		})
	}
	if _, err := oomVictimTaskArgFromProto(&btf.FuncProto{}); err == nil {
		t.Fatal("missing victim argument accepted")
	}
}

func TestOOMPIDOnlyDetail(t *testing.T) {
	limited := normalize(wireEvent{Kind: 5, PID: 42, Operation: 1})
	if !limited.PIDOnly || limited.PID != 42 || limited.TGID != 0 || limited.Comm != "" || limited.ProcessStartNS != 0 || limited.CgroupID != 0 {
		t.Fatalf("limited victim identity was fabricated or lost: %+v", limited)
	}
	full := normalize(wireEvent{Kind: 5, PID: 42, TGID: 40})
	if full.PIDOnly || full.PID != 42 || full.TGID != 40 {
		t.Fatalf("task-pointer victim identity was downgraded: %+v", full)
	}
}
