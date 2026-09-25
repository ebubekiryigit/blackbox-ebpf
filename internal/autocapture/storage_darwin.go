//go:build darwin

package autocapture

import (
	"os"

	"golang.org/x/sys/unix"
)

func freeBytes(f *os.File) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
