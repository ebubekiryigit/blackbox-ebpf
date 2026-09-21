//go:build windows

package control

import "fmt"

func privateDirectory(string) error { return fmt.Errorf("recording requires Linux") }
