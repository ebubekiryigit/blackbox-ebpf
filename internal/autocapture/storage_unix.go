//go:build linux || darwin

package autocapture

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func checkOwner(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("automatic capture directory must be private and owned by the daemon user")
	}
	return nil
}
func lockDirectory(f *os.File) error {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("automatic capture directory is busy: %w", err)
	}
	return nil
}
