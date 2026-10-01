//go:build linux && integration

// Package kernelworkload supplies disposable I/O for real-kernel tests.
package kernelworkload

import (
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func Open(t *testing.T) *os.File {
	t.Helper()
	path := os.Getenv("BLACKBOX_TEST_BLOCK_DEVICE")
	if path == "" {
		f, err := os.CreateTemp(t.TempDir(), "io-workload")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		})
		return f
	}
	// vimto guests have a 9p/tmpfs root, which produces no block requests.
	// Only accept the dedicated scratch loop device created by .vimto.toml;
	// never write an arbitrary disk supplied through the environment.
	if path != "/dev/loop0" {
		t.Fatalf("kernel workload requires the dedicated VM loop device, got %q", path)
	}
	backing, err := os.ReadFile("/sys/block/loop0/loop/backing_file")
	if err != nil || strings.TrimSpace(string(backing)) != "/tmp/blackbox-kernel-test.img" {
		t.Fatalf("refusing non-test block device: backing=%q error=%v", backing, err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|unix.O_EXCL|unix.O_SYNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	return f
}

// Scheduling produces runnable waits even on an otherwise idle multi-CPU VM.
// Restore each thread's affinity before returning it to the Go runtime.
func Scheduling(t *testing.T) {
	t.Helper()
	var allowed unix.CPUSet
	if err := unix.SchedGetaffinity(0, &allowed); err != nil {
		t.Fatal(err)
	}
	if allowed.Count() == 0 {
		t.Fatal("no CPU available for scheduler workload")
	}
	var target unix.CPUSet
	cpu := 0
	for !allowed.IsSet(cpu) {
		cpu++
	}
	target.Set(cpu)
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			var previous unix.CPUSet
			if err := unix.SchedGetaffinity(0, &previous); err != nil {
				t.Error(err)
				return
			}
			if err := unix.SchedSetaffinity(0, &target); err != nil {
				t.Error(err)
				return
			}
			defer func() {
				if err := unix.SchedSetaffinity(0, &previous); err != nil {
					t.Error(err)
				}
			}()
			until := time.Now().Add(200 * time.Millisecond)
			for time.Now().Before(until) {
			}
		})
	}
	workers.Wait()
}
