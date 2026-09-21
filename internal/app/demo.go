package app

import (
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/version"
)

// Demo is deliberately synthetic and never substitutes for kernel recording.
func Demo() model.Capture {
	anchor := uint64(60 * time.Second)
	host := model.Host{Hostname: "synthetic-demo", Kernel: "synthetic (no eBPF)", Architecture: "portable", BootID: "synthetic", AnchorMonoNS: anchor, AnchorWall: time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)}
	health := model.Health{}
	for _, n := range model.Families {
		health.Sensors = append(health.Sensors, model.SensorHealth{Name: n, State: "healthy"})
	}
	c := model.Capture{Host: host, Manifest: model.Manifest{FormatVersion: model.FormatVersion, ApplicationVersion: version.String(), StartMonoNS: anchor, RequestedStartMonoNS: anchor, EndMonoNS: anchor + uint64(10*time.Second), Mode: "synthetic-demo", Health: health, Settings: (&Engine{Config: config.Default()}).Settings()}}
	for i := 0; i < 10; i++ {
		start := anchor + uint64(time.Duration(i)*time.Second)
		s := model.Segment{StartMonoNS: start, EndMonoNS: start + uint64(time.Second)}
		for _, n := range model.Families {
			m := model.Metric{Family: n, StartMonoNS: start, EndMonoNS: s.EndMonoNS}
			if n == "block_io" {
				m.Histogram[0] = 100
				m.Count = 100
				if i == 4 {
					m.Histogram[9] = 3
					m.Count += 3
					m.Anomalies = 3
					m.Critical = 3
				}
			}
			if n == "scheduler" {
				m.Histogram[1] = 100
				m.Count = 100
			}
			s.Metrics = append(s.Metrics, m)
		}
		if i == 4 {
			for j := 0; j < 3; j++ {
				s.Events = append(s.Events, model.Event{MonoNS: start + uint64(time.Duration(j+1)*100*time.Millisecond), Type: "block_io", Comm: "demo-database", PID: 1234, TGID: 1234, ProcessStartNS: 1, CPU: 0, LatencyNS: uint64(300 * time.Millisecond), Major: 8, Minor: 0, Bytes: 4096, Operation: "read"})
			}
		}
		c.Segments = append(c.Segments, s)
	}
	return c
}
