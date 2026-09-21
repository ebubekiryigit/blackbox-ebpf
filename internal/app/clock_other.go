//go:build !linux

package app

import (
	"fmt"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func Mono() (uint64, error)         { return 0, fmt.Errorf("recording requires Linux") }
func hostInfo() (model.Host, error) { return model.Host{}, fmt.Errorf("recording requires Linux") }
