//go:build !linux && !darwin && !windows

package terminal

func isTerminal(uintptr) bool { return false }
func columns(uintptr) int     { return 0 }
