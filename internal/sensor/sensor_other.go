//go:build !linux

package sensor

import (
	"fmt"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func open(config.Config) ([]Sensor, []model.SensorHealth, error) {
	return nil, nil, fmt.Errorf("recording requires Linux kernel >= 5.8 with BTF; offline analyze works on this platform")
}
