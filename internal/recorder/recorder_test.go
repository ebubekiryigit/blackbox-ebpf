package recorder

import (
	"bytes"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/capture"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestSnapshotIntervalBoundaryAndDelayedDelivery(t *testing.T) {
	r := New(5*time.Second, 1<<20, 10000000000)
	r.Event(model.Event{MonoNS: 10500000000, Type: "block_io"}, 11000000000)
	r.Metric(model.Metric{Family: "block_io", StartMonoNS: 10000000000, EndMonoNS: 11000000000, Count: 5}, 11000000000)
	r.Advance(12000000000)
	// The aggregate is stored after its interval, and a delayed event is stored
	// after observation. Both must be filtered by their own monotonic timestamps.
	c := r.Snapshot(1500*time.Millisecond, 12000000000, model.Host{}, r.Health(), "test")
	var b bytes.Buffer
	if e := (capture.Container{}).Write(&b, c); e != nil {
		t.Fatal(e)
	}
	decoded, e := (capture.Container{}).Read(&b)
	if e != nil {
		t.Fatal(e)
	}
	events, metrics := 0, 0
	for _, s := range decoded.Segments {
		events += len(s.Events)
		metrics += len(s.Metrics)
	}
	if events != 1 || metrics != 0 {
		t.Fatalf("events=%d metrics=%d", events, metrics)
	}
}
func TestTimeAndMemoryBoundAndImmutableSnapshot(t *testing.T) {
	r := New(3*time.Second, 1<<20, 10000000000)
	r.Event(model.Event{MonoNS: 10500000000, Type: "block_io", Comm: "db"}, 10500000000)
	frozen := r.Snapshot(time.Second, 11000000000, model.Host{}, r.Health(), "test")
	for i := 0; i < 20000; i++ {
		ns := uint64(12000000000 + i*1000)
		r.Event(model.Event{MonoNS: ns, Type: "scheduler", Comm: "storm"}, ns)
	}
	h := r.Health()
	if h.RetainedBytes > h.MaxBytes || h.RecorderDrops == 0 {
		t.Fatalf("budget not enforced: %+v", h)
	}
	if len(frozen.Segments[0].Events) != 1 || frozen.Segments[0].Events[0].Comm != "db" {
		t.Fatal("snapshot mutated")
	}
	r.Advance(20000000000)
	if len(r.sealed) != 0 {
		t.Fatal("time-expired history retained")
	}
}
func BenchmarkEventStorm(b *testing.B) {
	r := New(5*time.Minute, 32<<20, 1)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ns := uint64(time.Second) + uint64(i)*uint64(time.Millisecond)
		r.Event(model.Event{MonoNS: ns, Type: "block_io", Comm: "db"}, ns)
	}
}

func BenchmarkSnapshotWhileRecording(b *testing.B) {
	r := New(5*time.Minute, 32<<20, uint64(time.Second))
	now := uint64(time.Second)
	for i := 0; i < 300*256; i++ {
		now = uint64(time.Second) + uint64(i)*uint64(time.Second/256)
		r.Event(model.Event{MonoNS: now, Type: "block_io", Comm: "db"}, now)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := r.Snapshot(time.Minute, now, model.Host{}, r.Health(), "bench")
		if len(c.Segments) == 0 {
			b.Fatal("missing snapshot")
		}
	}
}

func BenchmarkMetricPolling(b *testing.B) {
	r := New(5*time.Minute, 32<<20, uint64(time.Second))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		end := uint64(time.Second) + uint64(i/4+1)*uint64(time.Second)
		r.Metric(model.Metric{Family: model.Families[i%4], StartMonoNS: end - uint64(time.Second), EndMonoNS: end, Count: 100}, end)
	}
}

func TestActiveSnapshotAndMetricCapacityBudget(t *testing.T) {
	now := uint64(10 * time.Second)
	r := New(time.Minute, 1<<20, now)
	r.Event(model.Event{MonoNS: now, Comm: "before"}, now)
	r.Metric(model.Metric{Family: "scheduler", StartMonoNS: now, EndMonoNS: now, Count: 1}, now)
	frozen := r.Snapshot(time.Second, now, model.Host{}, r.Health(), "test")
	for i := 0; i < 10000; i++ {
		r.Metric(model.Metric{Family: "scheduler", StartMonoNS: now, EndMonoNS: now, Count: uint64(i + 2)}, now)
	}
	r.Event(model.Event{MonoNS: now, Comm: "after"}, now)
	if len(frozen.Segments) != 1 || len(frozen.Segments[0].Events) != 1 || len(frozen.Segments[0].Metrics) != 1 || frozen.Segments[0].Metrics[0].Count != 1 {
		t.Fatal("mutable segment changed a published snapshot")
	}
	if h := r.Health(); h.RetainedBytes > h.MaxBytes || h.RecorderDrops == 0 {
		t.Fatalf("metric capacity budget not enforced: %+v", h)
	}
}

func TestSnapshotSelectionsWithDelayedObservations(t *testing.T) {
	r := New(time.Minute, 8<<20, uint64(10*time.Second))
	var events []model.Event
	var metrics []model.Metric
	for i := 1; i <= 40; i++ {
		now := uint64(10*time.Second) + uint64(i)*uint64(250*time.Millisecond)
		e := model.Event{MonoNS: now - uint64(i%7)*uint64(100*time.Millisecond), PID: uint32(i)}
		m := model.Metric{Family: "scheduler", StartMonoNS: now - uint64(time.Second), EndMonoNS: now, Count: uint64(i)}
		r.Event(e, now)
		r.Metric(m, now)
		events = append(events, e)
		metrics = append(metrics, m)
	}
	now := uint64(20 * time.Second)
	for _, last := range []time.Duration{250 * time.Millisecond, 1500 * time.Millisecond, 3 * time.Second, 10 * time.Second} {
		c := r.Snapshot(last, now, model.Host{}, r.Health(), "test")
		gotEvents, gotMetrics := map[uint32]bool{}, map[uint64]bool{}
		for _, s := range c.Segments {
			for _, e := range s.Events {
				gotEvents[e.PID] = true
			}
			for _, m := range s.Metrics {
				gotMetrics[m.Count] = true
			}
		}
		for _, e := range events {
			if want := e.MonoNS >= c.Manifest.StartMonoNS; gotEvents[e.PID] != want {
				t.Fatalf("last=%s event=%d selection incorrect", last, e.PID)
			}
		}
		for _, m := range metrics {
			if want := m.StartMonoNS >= c.Manifest.StartMonoNS; gotMetrics[m.Count] != want {
				t.Fatalf("last=%s metric=%d selection incorrect", last, m.Count)
			}
		}
	}
}
