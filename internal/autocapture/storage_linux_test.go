//go:build linux

package autocapture

import "testing"

func TestAvailableBytesUsesFragmentSize(t *testing.T) {
	if got := availableBytes(3, 1024, 4096); got != 3072 {
		t.Fatalf("fragment size ignored: %d", got)
	}
	if got := availableBytes(3, 0, 4096); got != 12288 {
		t.Fatalf("zero fragment size fallback: %d", got)
	}
}
