//go:build linux

package app

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func Boot() (uint64, error) {
	var t unix.Timespec
	e := unix.ClockGettime(unix.CLOCK_BOOTTIME, &t)
	return uint64(t.Nano()), e
}

// Bracket realtime with boot-time reads so the two values have a close,
// explicit sampling point even when the process is preempted between syscalls.
func sampleClocks() (clockSample, error) {
	var best clockSample
	bestSpan := ^uint64(0)
	for range 3 {
		first, err := Boot()
		if err != nil {
			return clockSample{}, err
		}
		var wall unix.Timespec
		if err = unix.ClockGettime(unix.CLOCK_REALTIME, &wall); err != nil {
			return clockSample{}, err
		}
		last, err := Boot()
		if err != nil {
			return clockSample{}, err
		}
		if last < first {
			return clockSample{}, fmt.Errorf("CLOCK_BOOTTIME moved backward during sampling")
		}
		if span := last - first; span < bestSpan {
			bestSpan = span
			best = clockSample{bootNS: first + span/2, wall: time.Unix(wall.Sec, wall.Nsec).UTC()}
		}
		if bestSpan <= uint64(50*time.Millisecond) {
			break
		}
	}
	return best, nil
}
func hostInfo() (model.Host, error) {
	sample, e := sampleClocks()
	if e != nil {
		return model.Host{}, e
	}
	name, e := os.Hostname()
	if e != nil {
		return model.Host{}, e
	}
	kernel, e := os.ReadFile("/proc/sys/kernel/osrelease")
	if e != nil {
		return model.Host{}, e
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return model.Host{}, e
	}
	return model.Host{Hostname: name, Kernel: strings.TrimSpace(string(kernel)), Architecture: runtime.GOARCH, BootID: strings.TrimSpace(string(boot)), ClockSource: "boottime", AnchorMonoNS: sample.bootNS, AnchorWall: sample.wall}, nil
}
