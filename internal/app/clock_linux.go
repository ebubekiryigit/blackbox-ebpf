//go:build linux

package app

import (
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func Mono() (uint64, error) {
	var t unix.Timespec
	e := unix.ClockGettime(unix.CLOCK_MONOTONIC, &t)
	return uint64(t.Nano()), e
}
func hostInfo() (model.Host, error) {
	ns, e := Mono()
	if e != nil {
		return model.Host{}, e
	}
	wall := time.Now().UTC()
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
	return model.Host{Hostname: name, Kernel: strings.TrimSpace(string(kernel)), Architecture: runtime.GOARCH, BootID: strings.TrimSpace(string(boot)), AnchorMonoNS: ns, AnchorWall: wall}, nil
}
