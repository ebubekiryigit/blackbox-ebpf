//go:build !linux && !darwin

package autocapture

import (
	"fmt"
	"os"
)

func checkOwner(*os.File) error {
	return fmt.Errorf("automatic storage is unsupported on this platform")
}
func lockDirectory(*os.File) error {
	return fmt.Errorf("automatic storage is unsupported on this platform")
}
func freeBytes(*os.File) (uint64, error) {
	return 0, fmt.Errorf("automatic storage is unsupported on this platform")
}
