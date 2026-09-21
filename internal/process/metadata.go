// Package process enriches identity without collecting argv, environment or payloads.
package process

import (
	"container/list"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

// Linux USER_HZ is 100 on the supported amd64/arm64 architectures.
const procStartTickNS = 10000000

type identity struct {
	pid    uint32
	start  uint64
	cgroup uint64
}
type entry struct {
	key  identity
	path string
}
type Resolver struct {
	root      string
	limit     int
	pathLimit int
	items     map[identity]*list.Element
	lru       *list.List
	Failures  uint64
}

func New(root string, limit int) *Resolver {
	return NewWithPathLimit(root, limit, config.Default().Resources.MetadataPathBytes)
}
func NewWithPathLimit(root string, limit, pathLimit int) *Resolver {
	return &Resolver{root: root, limit: limit, pathLimit: pathLimit, items: map[identity]*list.Element{}, lru: list.New()}
}
func (r *Resolver) Enrich(e model.Event) model.Event {
	if e.TGID == 0 || e.ProcessStartNS == 0 {
		return e
	}
	key := identity{e.TGID, e.ProcessStartNS, e.CgroupID}
	if el := r.items[key]; el != nil {
		r.lru.MoveToFront(el)
		e.CgroupPath = el.Value.(entry).path
		return e
	}
	path, err := r.resolve(key)
	if err != nil {
		r.Failures++
	}
	el := r.lru.PushFront(entry{key, path})
	r.items[key] = el
	for r.lru.Len() > r.limit {
		last := r.lru.Back()
		delete(r.items, last.Value.(entry).key)
		r.lru.Remove(last)
	}
	e.CgroupPath = path
	return e
}
func (r *Resolver) resolve(k identity) (string, error) {
	dir := fmt.Sprintf("%s/%d", r.root, k.pid)
	readStart := func() (uint64, error) {
		b, e := os.ReadFile(dir + "/stat")
		if e != nil {
			return 0, e
		}
		end := strings.LastIndexByte(string(b), ')')
		if end < 0 {
			return 0, fmt.Errorf("invalid proc stat")
		}
		f := strings.Fields(string(b[end+1:]))
		if len(f) < 20 {
			return 0, fmt.Errorf("short proc stat")
		}
		return strconv.ParseUint(f[19], 10, 64)
	}
	before, err := readStart()
	if err != nil {
		return "", err
	}
	// Linux exports process start time in USER_HZ ticks (100 on amd64/arm64).
	if before != k.start/procStartTickNS {
		return "", fmt.Errorf("process identity changed before enrichment")
	}
	b, err := os.ReadFile(dir + "/cgroup")
	if err != nil {
		return "", err
	}
	after, err := readStart()
	if err != nil || before != after {
		return "", fmt.Errorf("process exited or identity changed during enrichment")
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::") {
			path := strings.TrimPrefix(line, "0::")
			if len(path) > r.pathLimit {
				return "", fmt.Errorf("cgroup path exceeds metadata limit")
			}
			return path, nil
		}
	}
	return "", nil // v1 has multiple controller paths; don't invent a v2 identity.
}
