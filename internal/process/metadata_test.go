package process

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestExitedOrReusedPIDKeepsEvidenceAndBoundsCache(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "42")
	_ = os.Mkdir(dir, 0700)
	// Field 22 is starttime. A comm may itself contain spaces and parentheses.
	stat := "42 (database (worker)) S " + strings.Repeat("0 ", 18) + "1000 0\n"
	_ = os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0600)
	_ = os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::/services/database\n"), 0600)
	r := New(root, 2)
	event := model.Event{MonoNS: 100, Type: "block_io", PID: 42, TGID: 42, ProcessStartNS: 10000000000, Comm: "database"}
	got := r.Enrich(event)
	if got.CgroupPath != "/services/database" {
		t.Fatalf("metadata unresolved: %+v failures=%d", got, r.Failures)
	}
	event.ProcessStartNS = 9000000000
	got = r.Enrich(event)
	if got.CgroupPath != "" || got.Comm != "database" || r.Failures != 1 {
		t.Fatal("reused PID was misattributed or evidence lost")
	}
	for i := uint32(1); i < 10; i++ {
		r.Enrich(model.Event{TGID: i, ProcessStartNS: 1})
	}
	if len(r.items) > 2 {
		t.Fatal("unbounded metadata cache")
	}
}
