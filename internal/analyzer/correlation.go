package analyzer

import (
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

// Coincidence is an analysis rule, not proof of causation.
const coincidenceWindow = time.Second

type correlationProcess struct {
	tgid    uint32
	startNS uint64
}

type correlationIndex struct {
	process map[correlationProcess]int
	cgroup  map[uint64]int
}

func newCorrelationIndex() correlationIndex {
	return correlationIndex{process: make(map[correlationProcess]int), cgroup: make(map[uint64]int)}
}

func (index correlationIndex) match(e model.Event) int {
	match := -1
	if e.TGID != 0 && e.ProcessStartNS != 0 {
		if i, ok := index.process[correlationProcess{e.TGID, e.ProcessStartNS}]; ok {
			match = i
		}
	}
	if e.CgroupID > 1 {
		if i, ok := index.cgroup[e.CgroupID]; ok && (match < 0 || i < match) {
			match = i
		}
	}
	return match
}

func (index correlationIndex) add(e model.Event, i int) bool {
	added := false
	if e.TGID != 0 && e.ProcessStartNS != 0 {
		index.process[correlationProcess{e.TGID, e.ProcessStartNS}] = i
		added = true
	}
	if e.CgroupID > 1 {
		index.cgroup[e.CgroupID] = i
		added = true
	}
	return added
}

func (index correlationIndex) remove(e model.Event, i int) {
	if e.TGID != 0 && e.ProcessStartNS != 0 {
		key := correlationProcess{e.TGID, e.ProcessStartNS}
		if index.process[key] == i {
			delete(index.process, key)
		}
	}
	if e.CgroupID > 1 && index.cgroup[e.CgroupID] == i {
		delete(index.cgroup, e.CgroupID)
	}
}

// firstCoincidence returns one deterministic pair. Both indexes contain only
// entries from the current one-second window, including either event order.
func firstCoincidence(timeline []model.Event) (int, int, bool) {
	blocks, others := newCorrelationIndex(), newCorrelationIndex()
	active := []int(nil)
	head := 0
	for i, e := range timeline {
		for head < len(active) && e.MonoNS-timeline[active[head]].MonoNS > uint64(coincidenceWindow) {
			old := active[head]
			if timeline[old].Type == "block_io" {
				blocks.remove(timeline[old], old)
			} else {
				others.remove(timeline[old], old)
			}
			head++
		}
		if head == len(active) {
			active = nil
			head = 0
		} else if head >= len(active)/2 && head > 0 {
			active = active[:copy(active, active[head:])]
			head = 0
		}
		current, opposite := &blocks, &others
		if e.Type != "block_io" {
			current, opposite = &others, &blocks
		}
		if prior := opposite.match(e); prior >= 0 {
			return prior, i, true
		}
		if current.add(e, i) {
			active = append(active, i)
		}
	}
	return 0, 0, false
}
