//go:build darwin

package terminal

import "golang.org/x/sys/unix"

func isTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TIOCGETA)
	return err == nil
}
func columns(fd uintptr) int {
	w, err := unix.IoctlGetWinsize(int(fd), unix.TIOCGWINSZ)
	if err != nil {
		return 0
	}
	return int(w.Col)
}
