//go:build !windows

package control

import (
	"fmt"
	"os"
	"syscall"
)

func privateDirectory(path string) error {
	info, e := os.Stat(path)
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("control socket directory must be owned by the daemon user and not group/world writable: %s", path)
	}
	return nil
}
