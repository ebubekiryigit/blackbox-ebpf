//go:build linux

package sensor

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestDecodeWireEventRejectsMalformedDetails(t *testing.T) {
	encode := func(t *testing.T, event wireEvent) []byte {
		t.Helper()
		var out bytes.Buffer
		if err := binary.Write(&out, binary.LittleEndian, event); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	valid := encode(t, wireEvent{Kind: 2, PID: 42})
	tests := []struct {
		name string
		raw  []byte
		fail string
	}{
		{name: "valid", raw: valid},
		{name: "truncated", raw: valid[:len(valid)-1], fail: "record size"},
		{name: "oversized", raw: append(append([]byte(nil), valid...), 0), fail: "record size"},
		{name: "unknown kind", raw: encode(t, wireEvent{Kind: 99}), fail: "unknown detail event kind"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event, err := decodeWireEvent(test.raw)
			if test.fail == "" {
				if err != nil || event.Type != "scheduler" || event.PID != 42 {
					t.Fatalf("valid detail changed: event=%+v err=%v", event, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.fail) {
				t.Fatalf("malformed detail accepted or opaque: %v", err)
			}
		})
	}
}
