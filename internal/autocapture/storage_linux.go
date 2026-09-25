//go:build linux

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
	return availableBytes(uint64(st.Bavail), uint64(st.Frsize), uint64(st.Bsize)), nil
}

func availableBytes(blocks, fragmentSize, blockSize uint64) uint64 {
	if fragmentSize == 0 {
		fragmentSize = blockSize
	}
	return blocks * fragmentSize
}
