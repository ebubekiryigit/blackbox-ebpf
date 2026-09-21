package sensor

import (
	"context"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

type Sink func(model.Event)
type Sensor interface {
	Name() string
	Start(context.Context, Sink) error
	Snapshot(start, end uint64) (model.Metric, error)
	Health() model.SensorHealth
	Close() error
}

func Open(c config.Config) ([]Sensor, []model.SensorHealth, error) { return open(c) }
