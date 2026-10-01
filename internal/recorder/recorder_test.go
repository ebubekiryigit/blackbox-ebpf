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
	// after observation. Both must be filtered by their own recorder timestamps.
	host := model.Host{ClockSource: "boottime", AnchorMonoNS: 10000000000, AnchorWall: time.Date(2026, 9, 28, 7, 0, 0, 0, time.UTC)}
	c := r.Snapshot(1500*time.Millisecond, 12000000000, host, r.Health(), "test")
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

func TestLastWindowExcludesEventsBeforeOneHourSuspend(t *testing.T) {
	start := uint64(100 * time.Hour)
	r := NewWithSegmentInterval(2*time.Hour, 1<<20, time.Second, start)
	if !r.Event(model.Event{MonoNS: start, Type: "oom", Comm: "before-suspend"}, start) {
		t.Fatal("pre-suspend event was not retained")
	}
	r.Metric(model.Metric{Family: "scheduler", StartMonoNS: start, EndMonoNS: start + uint64(time.Second), Count: 1}, start+uint64(time.Second))
	after := start + uint64(time.Hour)
	r.Advance(after)
	if !r.Event(model.Event{MonoNS: after, Type: "oom", Comm: "after-resume"}, after) {
		t.Fatal("post-resume event was not retained")
	}
	now := after + uint64(5*time.Second)
	c := r.Snapshot(10*time.Minute, now, model.Host{}, r.Health(), "test")
	if want := now - uint64(10*time.Minute); c.Manifest.RequestedStartMonoNS != want {
		t.Fatalf("--last used the wrong clock: got %d, want %d", c.Manifest.RequestedStartMonoNS, want)
	}
	var events []model.Event
	for _, segment := range c.Segments {
		events = append(events, segment.Events...)
		if len(segment.Metrics) != 0 {
			t.Fatal("pre-suspend aggregate entered the ten-minute window")
		}
	}
	if len(events) != 1 || events[0].Comm != "after-resume" {
		t.Fatalf("ten-minute window contains pre-suspend evidence: %+v", events)
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

func TestMemoryPressureCompactsOldDetailsButKeepsAggregates(t *testing.T) {
	start := uint64(time.Hour)
	r := NewWithSegmentInterval(time.Hour, 8<<10, time.Second, start)
	for i := uint64(0); i < 40; i++ {
		from := start + i*uint64(time.Second)
		end := from + uint64(time.Second)
		r.Event(model.Event{MonoNS: from, Type: "scheduler", Comm: "worker", LatencyNS: 100}, from)
		if !r.Metric(model.Metric{Family: "scheduler", StartMonoNS: from, EndMonoNS: end, Count: 1, Critical: 1, Histogram: model.Histogram{1}}, end) {
			t.Fatal("aggregate dropped instead of compacting old details")
		}
	}
	now := start + 40*uint64(time.Second)
	r.Advance(now)
	h := r.Health()
	if h.RetainedBytes > h.MaxBytes || h.RetainedFromNS != start || h.DetailedFromNS <= start || h.EvictedSegments == 0 {
		t.Fatalf("tiered retention did not preserve old metrics: %+v", h)
	}
	c := r.SnapshotWindow(start, now, model.Host{}, h, "test")
	if c.Manifest.AggregateOnlyUntilNS <= start || c.Manifest.AggregateOnlyUntilNS >= now {
		t.Fatalf("aggregate-only boundary is missing: %+v", c.Manifest)
	}
	var counts, details, covered uint64
	for _, segment := range c.Segments {
		details += uint64(len(segment.Events))
		for _, m := range segment.Metrics {
			counts += m.Count
			covered += m.EndMonoNS - m.StartMonoNS
		}
	}
	if counts != 40 || covered != 40*uint64(time.Second) || details >= 40 {
		t.Fatalf("compaction changed counts/coverage or retained every detail: counts=%d covered=%d details=%d", counts, covered, details)
	}
	frozen := c.Segments[0].Metrics[0].Count
	for i := uint64(40); i < 80; i++ {
		from := start + i*uint64(time.Second)
		r.Metric(model.Metric{Family: "scheduler", StartMonoNS: from, EndMonoNS: from + uint64(time.Second), Count: 1}, from+uint64(time.Second))
	}
	if c.Segments[0].Metrics[0].Count != frozen {
		t.Fatal("later rollup writes changed an already selected snapshot")
	}
}

func TestLongHistoryKeepsAggregatesWithinDefaultBudget(t *testing.T) {
	const seconds = 24 * 60 * 60
	start := uint64(time.Hour)
	r := NewWithSegmentInterval(24*time.Hour, 32<<20, time.Second, start)
	for i := uint64(0); i < seconds; i++ {
		from := start + i*uint64(time.Second)
		end := from + uint64(time.Second)
		for _, family := range model.Families {
			if !r.Metric(model.Metric{Family: family, StartMonoNS: from, EndMonoNS: end, Count: 1}, end) {
				t.Fatalf("aggregate dropped at second %d", i)
			}
		}
	}
	now := start + seconds*uint64(time.Second)
	h := r.Health()
	if h.RetainedBytes > h.MaxBytes || h.RetainedFromNS > start+uint64(time.Minute) || h.DetailedFromNS <= start {
		t.Fatalf("24-hour aggregate tier did not fit: %+v", h)
	}
	c := r.SnapshotWindow(start, now, model.Host{}, h, "test")
	var count uint64
	for _, s := range c.Segments {
		for _, m := range s.Metrics {
			count += m.Count
		}
	}
	if count != seconds*uint64(len(model.Families)) || c.Manifest.AggregateOnlyUntilNS == 0 {
		t.Fatalf("24-hour aggregate total changed: count=%d marker=%d", count, c.Manifest.AggregateOnlyUntilNS)
	}
	// The representative idle workload must remain writable with the default
	// archive limits, not just fit the in-memory recorder accounting budget.
	c.Host = model.Host{ClockSource: "boottime", AnchorMonoNS: start, AnchorWall: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	var encoded bytes.Buffer
	if err := (capture.Container{}).Write(&encoded, c); err != nil {
		t.Fatal(err)
	}
	if decoded, err := (capture.Container{}).Read(&encoded); err != nil || len(decoded.Segments) != len(c.Segments) {
		t.Fatalf("24-hour aggregate capture did not round-trip: %v", err)
	}
}

func TestAggregateOnlyBoundaryUsesSelectedIntervals(t *testing.T) {
	start := uint64(time.Hour)
	r := NewWithSegmentInterval(time.Hour, 1<<20, time.Second, start)
	r.rollupActive = &retained{segment: model.Segment{
		StartMonoNS: start,
		EndMonoNS:   start + uint64(50*time.Second),
		Metrics: []model.Metric{
			{Family: "scheduler", StartMonoNS: start, EndMonoNS: start + uint64(10*time.Second), Count: 10},
			{Family: "scheduler", StartMonoNS: start + uint64(20*time.Second), EndMonoNS: start + uint64(25*time.Second), Count: 5},
			{Family: "scheduler", StartMonoNS: start + uint64(30*time.Second), EndMonoNS: start + uint64(50*time.Second), Count: 20},
		},
	}, minNS: start, maxNS: start + uint64(50*time.Second)}
	c := r.SnapshotWindow(start+uint64(15*time.Second), start+uint64(40*time.Second), model.Host{
		ClockSource: "boottime", AnchorMonoNS: start, AnchorWall: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	}, r.Health(), "test")
	if got, want := c.Manifest.AggregateOnlyUntilNS, start+uint64(25*time.Second); got != want {
		t.Fatalf("aggregate-only boundary=%d, want last selected metric end %d", got, want)
	}
	var encoded bytes.Buffer
	if err := (capture.Container{}).Write(&encoded, c); err != nil {
		t.Fatal(err)
	}
	if _, err := (capture.Container{}).Read(&encoded); err != nil {
		t.Fatalf("partial cold window did not round-trip: %v", err)
	}
}

func TestShortHistoryKeepsDetailsUntilBudgetPressure(t *testing.T) {
	start := uint64(time.Hour)
	r := NewWithSegmentInterval(5*time.Minute, 32<<20, time.Second, start)
	for i := uint64(0); i < 5*60; i++ {
		from := start + i*uint64(time.Second)
		if !r.Event(model.Event{MonoNS: from, Type: "scheduler"}, from) {
			t.Fatal("short-history detail was dropped without budget pressure")
		}
	}
	now := start + 5*uint64(time.Minute)
	r.Advance(now)
	if h := r.Health(); h.DetailedFromNS != start || h.EvictedSegments != 0 {
		t.Fatalf("unexpected fixed detail cutoff: %+v", h)
	}
}

func TestAggregateBudgetEvictionReportsActualHistory(t *testing.T) {
	start := uint64(time.Hour)
	r := NewWithSegmentInterval(3*time.Hour, 8<<10, time.Minute, start)
	for i := uint64(0); i < 120; i++ {
		from := start + i*uint64(time.Minute)
		end := from + uint64(time.Minute)
		if !r.Metric(model.Metric{Family: "scheduler", StartMonoNS: from, EndMonoNS: end, Count: 1}, end) {
			t.Fatalf("current aggregate rejected at minute %d", i)
		}
	}
	now := start + 120*uint64(time.Minute)
	h := r.Health()
	if h.RetainedBytes > h.MaxBytes || h.AggregateEvictions == 0 || h.RetainedFromNS <= start {
		t.Fatalf("old aggregates were not evicted or actual span was hidden: %+v", h)
	}
	c := r.SnapshotWindow(start, now, model.Host{}, h, "test")
	if c.Manifest.RequestedStartMonoNS != start || c.Manifest.StartMonoNS != h.RetainedFromNS {
		t.Fatalf("truncated requested history was not recorded: %+v", c.Manifest)
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

func TestSnapshotFixedWindowAfterWriterDelay(t *testing.T) {
	r := New(10*time.Second, 1<<20, uint64(time.Second))
	for i := 1; i <= 10; i++ {
		now := uint64(time.Duration(i) * time.Second)
		r.Event(model.Event{Type: "oom", MonoNS: now}, now)
		r.Metric(model.Metric{Family: "oom", StartMonoNS: now - uint64(time.Second), EndMonoNS: now}, now)
	}
	r.Advance(uint64(12 * time.Second))
	c := r.SnapshotWindow(uint64(3*time.Second), uint64(8*time.Second), model.Host{}, r.Health(), "ebpf")
	if c.Manifest.EndMonoNS != uint64(8*time.Second) || c.Manifest.RequestedStartMonoNS != uint64(3*time.Second) {
		t.Fatal("window moved to write time")
	}
	var events int
	for _, s := range c.Segments {
		for _, e := range s.Events {
			events++
			if e.MonoNS < uint64(3*time.Second) || e.MonoNS > uint64(8*time.Second) {
				t.Fatal("event outside fixed window")
			}
		}
		for _, m := range s.Metrics {
			if m.StartMonoNS < uint64(3*time.Second) || m.EndMonoNS > uint64(8*time.Second) {
				t.Fatal("partial interval included")
			}
		}
	}
	if events != 6 {
		t.Fatalf("events=%d", events)
	}
	r.Advance(uint64(30 * time.Second))
	empty := r.SnapshotWindow(uint64(3*time.Second), uint64(8*time.Second), model.Host{}, r.Health(), "ebpf")
	if empty.Manifest.StartMonoNS != empty.Manifest.EndMonoNS || len(empty.Segments) != 0 {
		t.Fatalf("invalid evicted window: %+v", empty)
	}
	if len(c.Segments) == 0 {
		t.Fatal("selected immutable history lost during eviction")
	}
}
