//go:build windows

package terminal

import "golang.org/x/sys/windows"

func isTerminal(fd uintptr) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(fd), &mode) == nil && mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
}
func columns(fd uintptr) int {
	var info windows.ConsoleScreenBufferInfo
	if windows.GetConsoleScreenBufferInfo(windows.Handle(fd), &info) != nil {
		return 0
	}
	return int(info.Window.Right - info.Window.Left + 1)
}
