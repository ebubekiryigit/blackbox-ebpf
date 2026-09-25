package autocapture

import (
	"errors"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func metric(family string, start, end, n uint64) model.Metric {
	m := model.Metric{Family: family, StartMonoNS: seconds(start), EndMonoNS: seconds(end), Critical: n}
	if family == "oom" {
		m.Count = n
	}
	return m
}
func seconds(n uint64) uint64 { return n * uint64(time.Second) }

func TestFixedWindowsCoalesceAndStartConsecutiveIncidents(t *testing.T) {
	c := New(config.Default(), model.Families)
	c.Observe(metric("block_io", 99, 100, 2), seconds(100))
	c.Observe(metric("scheduler", 104, 105, 3), seconds(105))
	c.Observe(metric("block_io", 108, 109, 4), seconds(109))
	c.Observe(metric("oom", 109, 110, 1), seconds(110))
	if end, ok := c.Deadline(); !ok || end != seconds(110) {
		t.Fatalf("first window moved: %d %v", end, ok)
	}
	// A later trigger is held for the next capture, even before the first
	// capture has been selected or while its file is being written.
	c.Observe(metric("oom", 110, 111, 2), seconds(111))
	first := c.Begin()
	if h := c.Health(); h.State != "writing" || h.PendingUntilNS != seconds(121) {
		t.Fatalf("writer and waiting window status: %+v", h)
	}
	if first.DetectedMonoNS != seconds(100) || first.EndMonoNS != seconds(110) || len(first.Triggers) != 3 || first.Triggers[0].Count != 6 || first.Triggers[2].Count != 1 {
		t.Fatalf("first incident changed: %+v", first)
	}
	c.Observe(metric("oom", 111, 112, 1), seconds(112))
	if first.Triggers[2].Count != 1 {
		t.Fatal("writer changed already selected evidence")
	}
	c.Finish("/captures/first.bbx", time.Unix(111, 0), nil)
	if end, ok := c.Deadline(); !ok || end != seconds(121) {
		t.Fatalf("second incident missing: %d %v", end, ok)
	}
	second := c.Begin()
	if second.Triggers[0].Count != 3 || second.DetectedMonoNS != seconds(111) || second.EndMonoNS != seconds(121) {
		t.Fatalf("second incident incorrect: %+v", second)
	}
	c.Finish("/captures/second.bbx", time.Unix(121, 0), nil)
	c.Observe(metric("oom", 121, 122, 1), seconds(122))
	if end, ok := c.Deadline(); !ok || end != seconds(132) || c.Health().Saved != 2 {
		t.Fatalf("did not immediately rearm: %+v", c.Health())
	}
}

func TestTriggerSelectionAndAggregateOnlyDetection(t *testing.T) {
	for _, tt := range []struct {
		name                         string
		family                       string
		enabled, available, selected []string
		critical, count              uint64
		want                         bool
	}{
		{"critical block", "block_io", model.Families, model.Families, []string{"block_io"}, 1, 1, true},
		{"warn only", "scheduler", model.Families, model.Families, []string{"scheduler"}, 0, 20, false},
		{"oom", "oom", model.Families, model.Families, []string{"oom"}, 0, 1, true},
		{"tcp", "tcp", model.Families, model.Families, []string{"oom"}, 1, 1, false},
		{"disabled", "oom", []string{"tcp"}, model.Families, []string{"oom"}, 0, 1, false},
		{"unavailable", "oom", model.Families, []string{"block_io"}, []string{"oom"}, 0, 1, false},
		{"unselected", "block_io", model.Families, model.Families, []string{"oom"}, 1, 1, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Enabled, cfg.AutoCapture.Sensors = tt.enabled, tt.selected
			c := New(cfg, tt.available)
			c.Observe(model.Metric{Family: tt.family, StartMonoNS: 1, EndMonoNS: 2, Count: tt.count, Critical: tt.critical, Loss: model.Counters{Suppressed: 1000}}, 2)
			if _, got := c.Deadline(); got != tt.want {
				t.Fatalf("triggered=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestZeroPostWindowFailureAndUnavailableSources(t *testing.T) {
	cfg := config.Default()
	cfg.AutoCapture.After = 0
	c := New(cfg, model.Families)
	c.Observe(metric("block_io", 1, 1, 2), seconds(1))
	if _, ok := c.Deadline(); ok {
		t.Fatal("startup interval triggered")
	}
	c.Observe(metric("block_io", 1, 2, 1), seconds(2))
	c.Observe(metric("block_io", 2, 3, 1), seconds(3))
	first := c.Begin()
	if first.EndMonoNS != seconds(2) || first.Triggers[0].Count != 1 {
		t.Fatal("zero-post window swallowed next trigger")
	}
	c.Finish("", time.Time{}, errors.New("disk unavailable"))
	if c.Health().Failures != 1 || c.Health().LastError == "" {
		t.Fatal("failure not visible")
	}
	if end, ok := c.Deadline(); !ok || end != seconds(3) {
		t.Fatal("failure discarded the next incident")
	}
	c.Begin()
	c.Finish("/captures/recovered.bbx", time.Unix(3, 0), nil)
	if c.Health().Saved != 1 || c.Health().LastError != "" {
		t.Fatal("successful retry not reflected")
	}
	c.Unavailable("block_io")
	c.Unavailable("scheduler")
	c.Unavailable("oom")
	if c.Health().State != "inactive" {
		t.Fatal("unavailable sources still armed")
	}
}

func TestBusyWriterKeepsBoundedTriggerBacklog(t *testing.T) {
	c := New(config.Default(), model.Families)
	for i := 1; i <= 20000; i++ {
		family := []string{"block_io", "scheduler", "oom"}[i%3]
		start := seconds(100) + uint64(i-1)*uint64(time.Millisecond)
		end := start + uint64(time.Millisecond)
		c.Observe(model.Metric{Family: family, StartMonoNS: start, EndMonoNS: end, Count: 1, Critical: 1}, end)
	}
	first := c.Begin()
	if len(first.Triggers) != 3 {
		t.Fatal("first window lost a trigger family")
	}
	c.Finish("/captures/first.bbx", time.Time{}, nil)
	second := c.Begin()
	c.Finish("/captures/second.bbx", time.Time{}, nil)
	var captured uint64
	for _, incident := range []model.AutoIncident{first, second} {
		for _, trigger := range incident.Triggers {
			captured += trigger.Count
		}
	}
	if captured != 20000 || c.Health().Detected != captured || c.Health().Saved != 2 {
		t.Fatalf("lost or unbounded trigger accounting: captured=%d health=%+v", captured, c.Health())
	}

	c.Observe(metric("oom", 199, 200, 1), seconds(200))
	c.Observe(metric("oom", 210, 211, 1), seconds(211))
	c.Observe(metric("oom", 229, 230, 1), seconds(230))
	first = c.Begin()
	c.Finish("/captures/third.bbx", time.Time{}, nil)
	second = c.Begin()
	if second.EndMonoNS != seconds(240) || second.AfterNS != seconds(29) || second.Triggers[0].Count != 2 || !second.Valid(second.EndMonoNS) {
		t.Fatalf("waiting window did not cover new triggers: %+v", second)
	}
}

func BenchmarkAutomaticAggregateObservation(b *testing.B) {
	c := New(config.Default(), model.Families)
	m := metric("scheduler", 99, 100, 0)
	b.ReportAllocs()
	for b.Loop() {
		c.Observe(m, seconds(100))
	}
}
