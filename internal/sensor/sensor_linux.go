//go:build linux

package sensor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

type wireStats struct {
	Histogram                                              model.Histogram
	Count, Anomalies, Critical, Bytes, Retransmits, Resets uint64
	RingFailures, Suppressed, TrackingFailures, Unmatched  uint64
	BookkeepingCompletions                                 uint64
	BudgetSecond, BudgetUsed                               uint64
}
type wireEvent struct {
	MonoNS, LatencyNS, CgroupID, ProcessStartNS, Bytes uint64
	PID, TGID, CPU, Major, Minor, Kind, State          uint32
	SourcePort, DestinationPort, Family, Operation     uint16
	Comm                                               [16]byte
	SourceIP, DestinationIP                            [16]byte
	Padding                                            [4]byte
}
type kernelSensor struct {
	name           string
	collection     *ebpf.Collection
	links          []link.Link
	reader         *ringbuf.Reader
	previous       wireStats
	perCPU         []wireStats
	mu             sync.Mutex
	health         model.SensorHealth
	done           sync.WaitGroup
	closeOnce      sync.Once
	closeErr       error
	decodeFailures atomic.Uint64
	previousDecode uint64
}

func (s *kernelSensor) Name() string { return s.name }

type definition struct {
	name      string
	load      func() (*ebpf.CollectionSpec, error)
	threshold uint64
	critical  uint64
	hooks     map[string]string
}

func definitions(c config.Config) []definition {
	return []definition{
		{"block_io", loadBlock, uint64(c.BlockThreshold), uint64(c.BlockCritical), map[string]string{"issue": "block_rq_issue", "complete": "block_rq_complete"}},
		{"scheduler", loadSched, uint64(c.SchedulerThreshold), uint64(c.SchedulerCritical), map[string]string{"wakeup": "sched_wakeup", "wakeup_new": "sched_wakeup_new", "switch_task": "sched_switch", "exit_task": "sched_process_exit"}},
		{"tcp", loadTcp, 0, 0, map[string]string{"retransmit": "tcp_retransmit_skb", "send_reset": "tcp_send_reset", "receive_reset": "tcp_receive_reset"}},
		{"oom", loadOom, 0, 0, map[string]string{"victim": "mark_victim"}},
	}
}
func open(c config.Config) ([]Sensor, []model.SensorHealth, error) {
	return openDefinitions(c, definitions(c))
}
func openDefinitions(c config.Config, defs []definition) ([]Sensor, []model.SensorHealth, error) {
	if os.Geteuid() != 0 {
		return nil, nil, fmt.Errorf("recording initially requires root")
	}
	if _, e := os.Stat("/sys/kernel/btf/vmlinux"); e != nil {
		return nil, nil, fmt.Errorf("kernel BTF is required: %w", e)
	}
	if e := rlimit.RemoveMemlock(); e != nil {
		return nil, nil, fmt.Errorf("raise BPF memlock: %w", e)
	}
	cpus, e := ebpf.PossibleCPU()
	if e != nil {
		return nil, nil, e
	}
	var sensors []Sensor
	var unavailable []model.SensorHealth
	enabled := map[string]bool{}
	for _, n := range c.Enabled {
		enabled[n] = true
	}
	for _, d := range defs {
		if !enabled[d.name] {
			unavailable = append(unavailable, model.SensorHealth{Name: d.name, State: "disabled", Reason: "disabled by configuration"})
			continue
		}
		spec, err := d.load()
		if err == nil {
			constants := map[string]interface{}{"detail_rate": c.DetailRate, "possible_cpus": uint32(cpus)}
			// Unused constants are optimized away by Clang.
			for k := range constants {
				if spec.Variables[k] == nil {
					delete(constants, k)
				}
			}
			if spec.Variables["threshold_ns"] != nil {
				constants["threshold_ns"] = d.threshold
			}
			if spec.Variables["critical_threshold_ns"] != nil {
				constants["critical_threshold_ns"] = d.critical
			}
			if d.name == "block_io" {
				var index uint32
				index, err = blockRequestIndex()
				if err == nil {
					constants["rq_arg_index"] = index
				}
			}
			if err == nil {
				for name, value := range constants {
					if err = spec.Variables[name].Set(value); err != nil {
						break
					}
				}
			}
		}
		var col *ebpf.Collection
		if err == nil {
			configureMaps(spec, c.Resources)
			col, err = ebpf.NewCollection(spec)
		}
		s := &kernelSensor{name: d.name, collection: col, perCPU: make([]wireStats, cpus), health: model.SensorHealth{Name: d.name, State: "healthy"}}
		if err == nil {
			// All hooks of a family are required; partial coverage isn't labeled healthy.
			for program, hook := range d.hooks {
				var l link.Link
				l, err = link.AttachRawTracepoint(link.RawTracepointOptions{Name: hook, Program: col.Programs[program]})
				if err != nil {
					break
				}
				s.links = append(s.links, l)
			}
		}
		if err == nil {
			s.reader, err = ringbuf.NewReader(col.Maps["details"])
		}
		if err != nil {
			_ = s.Close()
			unavailable = append(unavailable, model.SensorHealth{Name: d.name, State: "unavailable", Reason: err.Error()})
			continue
		}
		s.health.KernelBytesKnown = true
		for _, m := range col.Maps {
			info, er := m.Info()
			if er != nil {
				s.health.KernelBytesKnown = false
				continue
			}
			if n, ok := info.Memlock(); ok {
				s.health.KernelBytes += n
			} else {
				s.health.KernelBytesKnown = false
			}
		}
		for _, p := range col.Programs {
			info, er := p.Info()
			if er != nil {
				s.health.KernelBytesKnown = false
				continue
			}
			if n, ok := info.Memlock(); ok {
				s.health.KernelBytes += n
			} else {
				s.health.KernelBytesKnown = false
			}
		}
		sensors = append(sensors, s)
	}
	if c.Strict {
		for _, h := range unavailable {
			if h.State == "unavailable" {
				for _, s := range sensors {
					_ = s.Close()
				}
				return nil, unavailable, fmt.Errorf("strict mode: %s could not initialize: %s", h.Name, h.Reason)
			}
		}
	}
	if len(sensors) == 0 {
		return nil, unavailable, fmt.Errorf("no kernel sensor could attach; check kernel hooks and BPF permissions: %v", unavailable)
	}
	return sensors, unavailable, nil
}
func blockRequestIndex() (uint32, error) {
	spec, e := btf.LoadKernelSpec()
	if e != nil {
		return 0, e
	}
	var t *btf.Typedef
	if e = spec.TypeByName("btf_trace_block_rq_issue", &t); e != nil {
		return 0, fmt.Errorf("cannot establish block tracepoint argument layout: %w", e)
	}
	ptr, ok := btf.UnderlyingType(t.Type).(*btf.Pointer)
	if !ok {
		return 0, fmt.Errorf("unexpected block tracepoint BTF")
	}
	proto, ok := btf.UnderlyingType(ptr.Target).(*btf.FuncProto)
	if !ok {
		return 0, fmt.Errorf("unexpected block tracepoint prototype")
	}
	for i, p := range proto.Params {
		pt, ok := btf.UnderlyingType(p.Type).(*btf.Pointer)
		if !ok {
			continue
		}
		st, ok := btf.UnderlyingType(pt.Target).(*btf.Struct)
		if ok && st.Name == "request" && (i == 1 || i == 2) {
			return uint32(i - 1), nil
		}
	}
	return 0, fmt.Errorf("unsupported block request tracepoint arguments")
}
func (s *kernelSensor) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.health.State = "error"
	s.health.Reason = err.Error()
}
func (s *kernelSensor) Start(ctx context.Context, sink Sink) error {
	s.done.Add(1)
	go func() {
		defer s.done.Done()
		var rec ringbuf.Record
		for {
			e := s.reader.ReadInto(&rec)
			if e != nil {
				if !errors.Is(e, ringbuf.ErrClosed) && ctx.Err() == nil {
					s.fail(e)
				}
				return
			}
			event, decodeErr := decodeWireEvent(rec.RawSample)
			if decodeErr != nil {
				s.decodeFailures.Add(1)
				continue
			}
			sink(event)
		}
	}()
	return nil
}
func decodeWireEvent(raw []byte) (model.Event, error) {
	want := binary.Size(wireEvent{})
	if len(raw) != want {
		return model.Event{}, fmt.Errorf("detail record size %d, want %d", len(raw), want)
	}
	var w wireEvent
	if _, err := binary.Decode(raw, binary.LittleEndian, &w); err != nil {
		return model.Event{}, err
	}
	event := normalize(w)
	if event.Type == "" {
		return model.Event{}, fmt.Errorf("unknown detail event kind %d", w.Kind)
	}
	return event, nil
}
func normalize(w wireEvent) model.Event {
	var kind string
	switch w.Kind {
	case 1:
		kind = "block_io"
	case 2:
		kind = "scheduler"
	case 3:
		kind = "tcp_retransmit"
	case 4, 6:
		kind = "tcp_reset"
	case 5:
		kind = "oom"
	}
	e := model.Event{MonoNS: w.MonoNS, Type: kind, PID: w.PID, TGID: w.TGID, Comm: strings.TrimRight(string(w.Comm[:]), "\x00"), ProcessStartNS: w.ProcessStartNS, CgroupID: w.CgroupID, CPU: w.CPU, LatencyNS: w.LatencyNS, Major: w.Major, Minor: w.Minor, Bytes: w.Bytes, SourcePort: w.SourcePort, DestinationPort: w.DestinationPort, State: w.State}
	if w.Kind == 1 {
		switch w.Operation {
		case 0:
			e.Operation = "read"
		case 1:
			e.Operation = "write"
		case 2:
			e.Operation = "flush"
		default:
			e.Operation = fmt.Sprintf("op:%d", w.Operation)
		}
	}
	if w.Family == 2 {
		e.SourceIP = netip.AddrFrom4([4]byte(w.SourceIP[:4])).String()
		e.DestinationIP = netip.AddrFrom4([4]byte(w.DestinationIP[:4])).String()
	} else if w.Family == 10 {
		e.SourceIP = netip.AddrFrom16(w.SourceIP).String()
		e.DestinationIP = netip.AddrFrom16(w.DestinationIP).String()
	}
	if (w.Kind == 3 || w.Kind == 4 || w.Kind == 6) && w.Operation&8 != 0 {
		// TCP provenance uses the block-only operation wire slot. The marker
		// distinguishes new records from legacy resets of unknown direction.
		e.TCPDirection = "sent"
		if w.Kind == 6 {
			e.TCPDirection = "received"
		}
		e.SocketContext = "none"
		if w.Operation&4 != 0 {
			e.SocketContext = "socket"
		}
		switch w.Operation & 3 {
		case 1:
			e.EndpointSource = "socket"
		case 2:
			e.EndpointSource = "packet_header"
		default:
			e.EndpointSource = "unavailable"
		}
		if w.Kind == 6 {
			// Socket fields are local/remote. A received reset flows remote→local.
			e.SourceIP, e.DestinationIP = e.DestinationIP, e.SourceIP
			e.SourcePort, e.DestinationPort = e.DestinationPort, e.SourcePort
		}
	}
	return e
}
func (s *kernelSensor) Snapshot(start, end uint64) (model.Metric, error) {
	key := uint32(0)
	if e := s.collection.Maps["aggregates"].Lookup(key, s.perCPU); e != nil {
		s.fail(e)
		return model.Metric{}, e
	}
	var sum wireStats
	for _, v := range s.perCPU {
		for i, n := range v.Histogram {
			sum.Histogram[i] += n
		}
		sum.Count += v.Count
		sum.Anomalies += v.Anomalies
		sum.Critical += v.Critical
		sum.Bytes += v.Bytes
		sum.Retransmits += v.Retransmits
		sum.Resets += v.Resets
		sum.RingFailures += v.RingFailures
		sum.Suppressed += v.Suppressed
		sum.TrackingFailures += v.TrackingFailures
		sum.Unmatched += v.Unmatched
		sum.BookkeepingCompletions += v.BookkeepingCompletions
	}
	p := s.previous
	s.previous = sum
	decodeFailures := s.decodeFailures.Load()
	m := model.Metric{Family: s.name, StartMonoNS: start, EndMonoNS: end, Count: delta(sum.Count, p.Count), Anomalies: delta(sum.Anomalies, p.Anomalies), Bytes: delta(sum.Bytes, p.Bytes), Retransmits: delta(sum.Retransmits, p.Retransmits), Resets: delta(sum.Resets, p.Resets), Loss: model.Counters{RingFailures: delta(sum.RingFailures, p.RingFailures), Suppressed: delta(sum.Suppressed, p.Suppressed), TrackingFailures: delta(sum.TrackingFailures, p.TrackingFailures), Unmatched: delta(sum.Unmatched, p.Unmatched), DecodeFailures: delta(decodeFailures, s.previousDecode)}}
	s.previousDecode = decodeFailures
	m.BookkeepingCompletions = delta(sum.BookkeepingCompletions, p.BookkeepingCompletions)
	m.Critical = delta(sum.Critical, p.Critical)
	for i, n := range sum.Histogram {
		m.Histogram[i] = delta(n, p.Histogram[i])
	}
	s.mu.Lock()
	s.health.Loss = model.Counters{RingFailures: sum.RingFailures, Suppressed: sum.Suppressed, TrackingFailures: sum.TrackingFailures, Unmatched: sum.Unmatched, DecodeFailures: decodeFailures}
	s.health.BookkeepingCompletions = sum.BookkeepingCompletions
	s.mu.Unlock()
	return m, nil
}
func delta(n, p uint64) uint64 {
	if n < p {
		return 0
	}
	return n - p
}
func (s *kernelSensor) Health() model.SensorHealth { s.mu.Lock(); defer s.mu.Unlock(); return s.health }
func (s *kernelSensor) Close() error {
	s.closeOnce.Do(func() {
		for _, l := range s.links {
			if err := l.Close(); err != nil && s.closeErr == nil {
				s.closeErr = err
			}
		}
		if s.reader != nil {
			if err := s.reader.Close(); err != nil && s.closeErr == nil {
				s.closeErr = err
			}
		}
		s.done.Wait()
		if s.collection != nil {
			s.collection.Close()
		}
	})
	return s.closeErr
}

// Size every operational map before creation; C sizes are loader placeholders.
func configureMaps(spec *ebpf.CollectionSpec, r config.Resources) {
	if m := spec.Maps["details"]; m != nil {
		m.MaxEntries = r.RingBytes
	}
	if m := spec.Maps["starts"]; m != nil {
		m.MaxEntries = r.BlockTrackingEntries
	}
	if m := spec.Maps["runnable"]; m != nil {
		m.MaxEntries = r.SchedulerTrackingEntries
	}
}
