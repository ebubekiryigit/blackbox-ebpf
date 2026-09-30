package analyzer

import (
	"fmt"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func correlationFinding(r Report) (Finding, bool) {
	for _, finding := range r.Findings {
		if finding.Category == "correlation" {
			return finding, true
		}
	}
	return Finding{}, false
}

func TestCorrelationHandlesBothTemporalOrdersAndKnownIdentity(t *testing.T) {
	const second = uint64(time.Second)
	block := model.Event{MonoNS: 2 * second, Type: "block_io", TGID: 17, ProcessStartNS: 100}
	scheduler := model.Event{MonoNS: 2*second + uint64(250*time.Millisecond), Type: "scheduler", TGID: 17, ProcessStartNS: 100}
	for _, test := range []struct {
		name   string
		events []model.Event
		match  bool
	}{
		{"block then scheduler", []model.Event{block, scheduler}, true},
		{"scheduler then block", []model.Event{{MonoNS: block.MonoNS - uint64(250*time.Millisecond), Type: "scheduler", TGID: 17, ProcessStartNS: 100}, block}, true},
		{"equal timestamps", []model.Event{block, model.Event{MonoNS: block.MonoNS, Type: "scheduler", TGID: 17, ProcessStartNS: 100}}, true},
		{"one second inclusive", []model.Event{block, model.Event{MonoNS: block.MonoNS + second, Type: "scheduler", TGID: 17, ProcessStartNS: 100}}, true},
		{"outside one second", []model.Event{block, model.Event{MonoNS: block.MonoNS + second + 1, Type: "scheduler", TGID: 17, ProcessStartNS: 100}}, false},
		{"older same-key event expires but newer one remains", []model.Event{{MonoNS: second, Type: "block_io", TGID: 17, ProcessStartNS: 100}, block, {MonoNS: 2*second + uint64(500*time.Millisecond), Type: "scheduler", TGID: 17, ProcessStartNS: 100}}, true},
		{"PID reused", []model.Event{block, model.Event{MonoNS: block.MonoNS + 1, Type: "scheduler", TGID: 17, ProcessStartNS: 101}}, false},
		{"unknown process start", []model.Event{block, model.Event{MonoNS: block.MonoNS + 1, Type: "scheduler", TGID: 17}}, false},
		{"cgroup only", []model.Event{{MonoNS: block.MonoNS, Type: "block_io", CgroupID: 55}, {MonoNS: block.MonoNS + 1, Type: "scheduler", CgroupID: 55}}, true},
		{"root cgroup is not an identity", []model.Event{{MonoNS: block.MonoNS, Type: "block_io", TGID: 17, ProcessStartNS: 100, CgroupID: 1}, {MonoNS: block.MonoNS + 1, Type: "scheduler", TGID: 18, ProcessStartNS: 200, CgroupID: 1}}, false},
		{"root cgroup is not an identity in reverse order", []model.Event{{MonoNS: block.MonoNS, Type: "scheduler", TGID: 18, ProcessStartNS: 200, CgroupID: 1}, {MonoNS: block.MonoNS + 1, Type: "block_io", TGID: 17, ProcessStartNS: 100, CgroupID: 1}}, false},
		{"root cgroup does not hide a matching process", []model.Event{{MonoNS: block.MonoNS, Type: "block_io", TGID: 17, ProcessStartNS: 100, CgroupID: 1}, {MonoNS: block.MonoNS + 1, Type: "scheduler", TGID: 17, ProcessStartNS: 100, CgroupID: 1}}, true},
		{"unknown identity", []model.Event{{MonoNS: block.MonoNS, Type: "block_io"}, {MonoNS: block.MonoNS + 1, Type: "scheduler"}}, false},
		{"same signal", []model.Event{block, {MonoNS: block.MonoNS + 1, Type: "block_io", TGID: 17, ProcessStartNS: 100}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := Analyze(model.Capture{Segments: []model.Segment{{Events: test.events}}})
			finding, found := correlationFinding(r)
			if found != test.match {
				t.Fatalf("correlation found=%t, want %t", found, test.match)
			}
			if found {
				if len(finding.Evidence) != 2 || finding.Evidence[0].Index < 0 || finding.Evidence[1].Index >= len(r.Timeline) || finding.Evidence[0].Index >= finding.Evidence[1].Index {
					t.Fatalf("invalid timeline evidence: %+v", finding.Evidence)
				}
			}
		})
	}
}

func TestCorrelationEmitsOneDeterministicPair(t *testing.T) {
	c := model.Capture{Segments: []model.Segment{{Events: []model.Event{
		{MonoNS: uint64(time.Second), Type: "block_io", TGID: 17, ProcessStartNS: 100},
		{MonoNS: uint64(time.Second) + 1, Type: "scheduler", TGID: 17, ProcessStartNS: 100},
		{MonoNS: uint64(time.Second) + 2, Type: "tcp_reset", TGID: 17, ProcessStartNS: 100},
	}}}}
	r := Analyze(c)
	count := 0
	for _, finding := range r.Findings {
		if finding.Category == "correlation" {
			count++
			if len(finding.Evidence) != 2 || finding.Evidence[0].Index != 0 || finding.Evidence[1].Index != 1 {
				t.Fatalf("unexpected evidence pair: %+v", finding.Evidence)
			}
		}
	}
	if count != 1 {
		t.Fatalf("got %d correlation findings, want one", count)
	}
}

func TestDenseBlockOnlyTimelineHasNoCorrelation(t *testing.T) {
	const count = 200000
	events := make([]model.Event, count)
	for i := range events {
		events[i] = model.Event{MonoNS: uint64(time.Second), Type: "block_io", TGID: 17, ProcessStartNS: 100}
	}
	r := Analyze(model.Capture{Segments: []model.Segment{{Events: events}}})
	if _, found := correlationFinding(r); found || len(r.Timeline) != count {
		t.Fatalf("dense block-only capture changed: finding=%t events=%d", found, len(r.Timeline))
	}
}

func BenchmarkAnalyze(b *testing.B) {
	for _, test := range []struct {
		name  string
		count int
		kind  string
	}{
		{"dense_block_2000", 2000, "block_io"},
		{"dense_block_4000", 4000, "block_io"},
		{"dense_block_200000", 200000, "block_io"},
		{"mixed_200000", 200000, "mixed"},
		{"oom_200000", 200000, "oom"},
	} {
		b.Run(test.name, func(b *testing.B) {
			events := make([]model.Event, test.count)
			for i := range events {
				kind := test.kind
				if kind == "mixed" {
					kind = "block_io"
					if i%2 != 0 {
						kind = "scheduler"
					}
				}
				events[i] = model.Event{MonoNS: uint64(time.Second), Type: kind, TGID: uint32(i%100 + 1), ProcessStartNS: 100, Comm: fmt.Sprintf("task%d", i%100)}
			}
			c := model.Capture{Segments: []model.Segment{{Events: events}}}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r := Analyze(c)
				if len(r.Timeline) != test.count {
					b.Fatal("incomplete timeline")
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(test.count), "events/op")
		})
	}
}
