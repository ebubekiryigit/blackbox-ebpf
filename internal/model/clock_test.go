package model

import (
	"testing"
	"time"
)

func TestWallUsesCaptureTimeBootAnchor(t *testing.T) {
	anchor := time.Date(2026, 9, 28, 7, 0, 0, 0, time.UTC)
	h := Host{ClockSource: "boottime", AnchorMonoNS: uint64(time.Hour), AnchorWall: anchor}
	for _, tc := range []struct {
		boot uint64
		want time.Time
	}{
		{uint64(50 * time.Minute), anchor.Add(-10 * time.Minute)},
		{uint64(time.Hour), anchor},
		{uint64(70 * time.Minute), anchor.Add(10 * time.Minute)},
	} {
		if got := h.Wall(tc.boot); !got.Equal(tc.want) {
			t.Errorf("Wall(%d) = %s, want %s", tc.boot, got, tc.want)
		}
	}
}
