// Package recorder owns a bounded rolling history. Its methods have one writer:
// the application event loop. Sealed segments are never mutated.
package recorder

import (
	"sort"
	"time"
	"unsafe"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/version"
)

// Conservative segment bookkeeping charge and geometric buffer growth policy.
// These are internal accounting/allocation rules, not collection limits.
const (
	segmentCost           int64 = 512
	initialEventCapacity        = 64
	initialMetricCapacity       = 8
)

type retained struct {
	segment model.Segment
	bytes   int64
	minNS   uint64
	maxNS   uint64
}

func (s *retained) observe(start, end uint64) {
	if start < s.minNS {
		s.minNS = start
	}
	if end > s.maxNS {
		s.maxNS = end
	}
}

type Recorder struct {
	started            uint64
	segmentInterval    uint64
	history            uint64
	max                int64
	bytes              int64
	rollups            []retained
	rollupActive       *retained
	rollupBucket       uint64
	sealed             []retained
	active             retained
	drops              uint64
	evictions          uint64
	aggregateEvictions uint64
}

func New(history time.Duration, max int64, now uint64) *Recorder {
	return NewWithSegmentInterval(history, max, config.Default().Resources.SegmentInterval, now)
}
func NewWithSegmentInterval(history time.Duration, max int64, segmentInterval time.Duration, now uint64) *Recorder {
	r := &Recorder{history: uint64(history), max: max, started: now, segmentInterval: uint64(segmentInterval)}
	r.open(now)
	return r
}
func (r *Recorder) open(now uint64) {
	r.active = retained{segment: model.Segment{StartMonoNS: now, EndMonoNS: now}, bytes: segmentCost, minNS: now, maxNS: now}
	r.bytes += segmentCost
}
func (r *Recorder) Advance(now uint64) {
	if now < r.active.segment.StartMonoNS {
		return
	}
	if now-r.active.segment.StartMonoNS >= r.segmentInterval {
		r.active.segment.EndMonoNS = r.active.segment.StartMonoNS + r.segmentInterval
		r.sealed = append(r.sealed, r.active)
		r.open(now)
	}
	r.active.segment.EndMonoNS = now
	for len(r.sealed) > 0 && now >= r.sealed[0].segment.EndMonoNS && now-r.sealed[0].segment.EndMonoNS >= r.history {
		r.dropRaw(false)
	}
	for len(r.rollups) > 0 && now >= r.rollups[0].segment.EndMonoNS && now-r.rollups[0].segment.EndMonoNS >= r.history {
		r.dropRollup(false)
	}
	if r.rollupActive != nil && now >= r.rollupActive.segment.EndMonoNS && now-r.rollupActive.segment.EndMonoNS >= r.history {
		r.dropRollup(false)
	}
	for r.bytes > r.max && len(r.sealed) > 0 {
		r.compactOldest()
	}
	for r.bytes > r.max && r.hasRollup() {
		r.dropRollup(true)
	}
}
func (r *Recorder) dropRaw(memory bool) {
	r.bytes -= r.sealed[0].bytes
	r.sealed[0] = retained{}
	r.sealed = r.sealed[1:]
	if memory {
		r.evictions++
	}
}
func (r *Recorder) room(cost int64, metric bool) bool {
	for r.bytes+cost > r.max && len(r.sealed) > 0 {
		r.compactOldest()
	}
	// Event detail must not displace retained aggregate evidence. A new metric
	// may replace the oldest summary only when no raw history remains to fold.
	for metric && r.bytes+cost > r.max && r.hasRollup() {
		r.dropRollup(true)
	}
	return r.bytes+cost <= r.max
}

func (r *Recorder) hasRollup() bool { return len(r.rollups) > 0 || r.rollupActive != nil }

func (r *Recorder) dropRollup(memory bool) {
	if memory {
		r.aggregateEvictions++
	}
	if len(r.rollups) > 0 {
		r.bytes -= r.rollups[0].bytes
		r.rollups[0] = retained{}
		r.rollups = r.rollups[1:]
		return
	}
	r.bytes -= r.rollupActive.bytes
	r.rollupActive = nil
}

// Compact only under budget pressure. The oldest details go first; their
// complete aggregate intervals remain available without a fixed hot-tier age.
func (r *Recorder) compactOldest() {
	old := r.sealed[0]
	r.dropRaw(true)
	if len(old.segment.Metrics) == 0 {
		return
	}
	bucket := old.segment.StartMonoNS / uint64(config.RollupInterval)
	if r.rollupActive != nil && bucket != r.rollupBucket {
		r.rollups = append(r.rollups, *r.rollupActive)
		r.rollupActive = nil
	}
	if r.rollupActive == nil {
		r.rollupBucket = bucket
		first := old.segment.Metrics[0]
		r.rollupActive = &retained{segment: model.Segment{StartMonoNS: first.StartMonoNS, EndMonoNS: first.EndMonoNS}, bytes: segmentCost, minNS: first.StartMonoNS, maxNS: first.EndMonoNS}
		r.bytes += segmentCost
	}
	for _, m := range old.segment.Metrics {
		r.addRollupMetric(m)
	}
}

func (r *Recorder) addRollupMetric(m model.Metric) {
	a := r.rollupActive
	a.observe(m.StartMonoNS, m.EndMonoNS)
	a.segment.StartMonoNS = min(a.segment.StartMonoNS, m.StartMonoNS)
	a.segment.EndMonoNS = max(a.segment.EndMonoNS, m.EndMonoNS)
	for i := range a.segment.Metrics {
		prev := &a.segment.Metrics[i]
		if prev.Family != m.Family || prev.EndMonoNS != m.StartMonoNS {
			continue
		}
		prev.EndMonoNS = m.EndMonoNS
		for j, n := range m.Histogram {
			prev.Histogram[j] += n
		}
		prev.Count += m.Count
		prev.Anomalies += m.Anomalies
		prev.Critical += m.Critical
		prev.Bytes += m.Bytes
		prev.Retransmits += m.Retransmits
		prev.Resets += m.Resets
		prev.BookkeepingCompletions += m.BookkeepingCompletions
		prev.Loss.RingFailures += m.Loss.RingFailures
		prev.Loss.Suppressed += m.Loss.Suppressed
		prev.Loss.DetailFailures += m.Loss.DetailFailures
		prev.Loss.TrackingFailures += m.Loss.TrackingFailures
		prev.Loss.Unmatched += m.Loss.Unmatched
		prev.Loss.DecodeFailures += m.Loss.DecodeFailures
		return
	}
	ms := a.segment.Metrics
	if len(ms) == cap(ms) {
		capacity := max(4, cap(ms)*2)
		next := make([]model.Metric, len(ms), capacity)
		copy(next, ms)
		ms = next
		cost := int64(capacity-cap(a.segment.Metrics)) * int64(unsafe.Sizeof(model.Metric{}))
		a.bytes += cost
		r.bytes += cost
	}
	a.segment.Metrics = append(ms, m)
}
func stringCost(e model.Event) int64 {
	return int64(len(e.Type) + len(e.Comm) + len(e.Operation) + len(e.SourceIP) + len(e.DestinationIP) + len(e.CgroupPath) + len(e.TCPDirection) + len(e.SocketContext) + len(e.EndpointSource))
}
func (r *Recorder) Event(e model.Event, now uint64) bool {
	r.Advance(now)
	// Delayed sensor delivery keeps the original canonical event timestamp.
	if e.MonoNS > now || now-e.MonoNS > r.history {
		r.drops++
		return false
	}
	cost := stringCost(e)
	es := r.active.segment.Events
	newCap := cap(es)
	if len(es) == cap(es) {
		if newCap == 0 {
			newCap = initialEventCapacity
		} else {
			newCap *= 2
		}
		cost += int64(newCap-cap(es)) * int64(unsafe.Sizeof(model.Event{}))
	}
	if !r.room(cost, false) {
		r.drops++
		return false
	}
	if len(es) == cap(es) {
		n := make([]model.Event, len(es), newCap)
		copy(n, es)
		es = n
	}
	r.active.segment.Events = append(es, e)
	r.active.observe(e.MonoNS, e.MonoNS)
	r.active.bytes += cost
	r.bytes += cost
	return true
}
func (r *Recorder) Metric(m model.Metric, now uint64) bool {
	r.Advance(now)
	ms := r.active.segment.Metrics
	cost := int64(len(m.Family))
	newCap := cap(ms)
	if len(ms) == cap(ms) {
		if newCap == 0 {
			newCap = 4
		} else {
			newCap *= 2
		}
		cost += int64(newCap-cap(ms)) * int64(unsafe.Sizeof(model.Metric{}))
	}
	if !r.room(cost, true) {
		r.drops++
		return false
	}
	// Account for backing capacity, including unused slots.
	if len(ms) == cap(ms) {
		n := make([]model.Metric, len(ms), newCap)
		copy(n, ms)
		ms = n
	}
	r.active.segment.Metrics = append(ms, m)
	r.active.observe(m.StartMonoNS, m.EndMonoNS)
	r.active.bytes += cost
	r.bytes += cost
	return true
}
func (r *Recorder) Health() model.Health {
	detailFrom := r.active.segment.StartMonoNS
	if len(r.sealed) > 0 {
		detailFrom = r.sealed[0].segment.StartMonoNS
	}
	from := detailFrom
	if len(r.rollups) > 0 {
		from = min(from, r.rollups[0].minNS)
	} else if r.rollupActive != nil {
		from = min(from, r.rollupActive.minNS)
	}
	return model.Health{RetainedBytes: r.bytes, MaxBytes: r.max, RetainedFromNS: from, DetailedFromNS: detailFrom, RecorderDrops: r.drops, EvictedSegments: r.evictions, AggregateEvictions: r.aggregateEvictions}
}
func (r *Recorder) Snapshot(last time.Duration, now uint64, host model.Host, health model.Health, mode string) model.Capture {
	r.Advance(now)
	start := uint64(0)
	if uint64(last) < now {
		start = now - uint64(last)
	}
	return r.SnapshotWindow(start, now, host, health, mode)
}

// SnapshotWindow selects a fixed past window without rewinding retention time.
// Callers advance the recorder with the current clock before selection.
func (r *Recorder) SnapshotWindow(start, now uint64, host model.Host, health model.Health, mode string) model.Capture {
	actual := start
	if from := r.Health().RetainedFromNS; actual < from {
		actual = min(from, now)
	}
	c := model.Capture{Host: host, Manifest: model.Manifest{FormatVersion: model.FormatVersion, ApplicationVersion: version.String(), StartMonoNS: actual, EndMonoNS: now, RequestedStartMonoNS: start, Health: health, Mode: mode}}
	c.Manifest.RecordingStartMonoNS = r.started
	first := sort.Search(len(r.sealed), func(i int) bool { return r.sealed[i].segment.EndMonoNS >= actual })
	c.Segments = make([]model.Segment, 0, len(r.sealed)-first+1)
	add := func(ret retained, immutable bool) {
		s := ret.segment
		if s.EndMonoNS < actual || s.StartMonoNS > now {
			return
		}
		contained := ret.minNS >= actual && ret.maxNS <= now
		if immutable && contained {
			c.Segments = append(c.Segments, s)
			return
		}
		// Only a boundary segment or the mutable active segment needs a bounded copy.
		out := model.Segment{StartMonoNS: s.StartMonoNS, EndMonoNS: s.EndMonoNS}
		if contained {
			out.Events = append([]model.Event(nil), s.Events...)
			out.Metrics = append([]model.Metric(nil), s.Metrics...)
			c.Segments = append(c.Segments, out)
			return
		}
		events, metrics := 0, 0
		for _, e := range s.Events {
			if e.MonoNS >= actual && e.MonoNS <= now {
				events++
			}
		}
		for _, m := range s.Metrics {
			if m.StartMonoNS >= actual && m.EndMonoNS <= now {
				metrics++
			}
		}
		out.Events = make([]model.Event, 0, events)
		out.Metrics = make([]model.Metric, 0, metrics)
		for _, e := range s.Events {
			if e.MonoNS >= actual && e.MonoNS <= now {
				out.Events = append(out.Events, e)
			}
		}
		// Include only complete aggregate intervals; a partial second isn't interpolated.
		for _, m := range s.Metrics {
			if m.StartMonoNS >= actual && m.EndMonoNS <= now {
				out.Metrics = append(out.Metrics, m)
			}
		}
		c.Segments = append(c.Segments, out)
	}
	markAggregateOnly := func(before int) {
		if len(c.Segments) == before {
			return
		}
		for _, metric := range c.Segments[len(c.Segments)-1].Metrics {
			c.Manifest.AggregateOnlyUntilNS = max(c.Manifest.AggregateOnlyUntilNS, metric.EndMonoNS)
		}
	}
	for _, s := range r.rollups {
		before := len(c.Segments)
		add(s, true)
		markAggregateOnly(before)
	}
	if r.rollupActive != nil {
		before := len(c.Segments)
		add(*r.rollupActive, false)
		markAggregateOnly(before)
	}
	for _, s := range r.sealed[first:] {
		add(s, true)
	}
	add(r.active, false)
	return c
}
