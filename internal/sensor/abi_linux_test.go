//go:build linux

package sensor

import (
	"encoding/binary"
	"reflect"
	"testing"

	"strings"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestEmbeddedWireABIAndConfiguredMapBudgets(t *testing.T) {
	cfg := config.Default()
	cfg.Resources.RingBytes = 128 << 10
	cfg.Resources.BlockTrackingEntries = 100
	cfg.Resources.SchedulerTrackingEntries = 200
	for _, def := range definitions(cfg) {
		spec, err := def.load()
		if err != nil {
			t.Fatal(err)
		}
		if int(spec.Maps["aggregates"].ValueSize) != binary.Size(wireStats{}) {
			t.Fatalf("%s stats wire ABI mismatch", def.name)
		}
		if spec.Maps["details"].MaxEntries != 1 {
			t.Fatal("embedded map has stale operational defaults; run make generate")
		}
		configureMaps(spec, cfg.Resources)
		if spec.Maps["details"].MaxEntries != cfg.Resources.RingBytes {
			t.Fatal("detail ring configuration ignored")
		}
		if m := spec.Maps["starts"]; m != nil && m.MaxEntries != cfg.Resources.BlockTrackingEntries {
			t.Fatal("block tracking configuration ignored")
		}
		if m := spec.Maps["runnable"]; m != nil && m.MaxEntries != cfg.Resources.SchedulerTrackingEntries {
			t.Fatal("scheduler tracking configuration ignored")
		}
	}
	// The generated block map embeds the exact C event type, including padding.
	generated := reflect.TypeFor[blockInflight]().Field(2).Type
	wire := reflect.TypeFor[wireEvent]()
	if generated.Size() != wire.Size() || binary.Size(reflect.New(generated).Elem().Interface()) != binary.Size(wireEvent{}) {
		t.Fatal("event wire ABI size mismatch")
	}
	for i := 0; i < wire.NumField(); i++ {
		field := wire.Field(i)
		if field.Name == "Padding" {
			continue
		}
		found := false
		for j := 0; j < generated.NumField(); j++ {
			other := generated.Field(j)
			if strings.EqualFold(field.Name, other.Name) {
				found = true
				if field.Offset != other.Offset || field.Type.Size() != other.Type.Size() {
					t.Fatal("event ABI field mismatch", field.Name)
				}
			}
		}
		if !found {
			t.Fatal("event field missing from generated C ABI", field.Name)
		}
	}
	if reflect.TypeFor[blockStats]().Field(1).Type.Len() != model.HistogramBuckets {
		t.Fatal("kernel/user histogram bucket mismatch")
	}
}
