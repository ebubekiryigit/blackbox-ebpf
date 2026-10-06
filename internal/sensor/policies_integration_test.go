//go:build linux && integration

package sensor

import (
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
)

func policyFixture(t *testing.T, rate uint32) *ebpf.Collection {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := loadPolicytest()
	if err != nil {
		t.Fatal(err)
	}
	configureMaps(spec, config.Default().Resources)
	if err = spec.Variables["detail_rate"].Set(rate); err != nil {
		t.Fatal(err)
	}
	c, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func runPolicy(c *ebpf.Collection, action, generation, now, critical uint64) (uint32, error) {
	if err := c.Maps["test_input"].Update(uint32(0), [4]uint64{action, generation, now, critical}, ebpf.UpdateAny); err != nil {
		return 0, err
	}
	ret, _, err := c.Programs["policies"].Test(make([]byte, 64))
	return ret, err
}

func TestRequestTimingRequeueAndPointerReuse(t *testing.T) {
	for _, tc := range []struct {
		name      string
		steps     [][3]uint64 // action, allocation generation, dispatch timestamp
		wantStart uint64
	}{
		{"first dispatch", [][3]uint64{{0, 1, 100}}, 100},
		{"repeated requeue", [][3]uint64{{0, 1, 100}, {1, 1, 0}, {0, 1, 200}, {1, 1, 0}, {0, 1, 300}}, 100},
		{"reuse after missed completion", [][3]uint64{{0, 1, 100}, {1, 1, 0}, {0, 2, 200}}, 200},
		{"reuse without requeue", [][3]uint64{{0, 1, 100}, {0, 2, 200}}, 200},
		{"missed requeue replaces start", [][3]uint64{{0, 1, 100}, {0, 1, 200}}, 200},
		{"requeue without issue", [][3]uint64{{1, 1, 0}, {0, 1, 200}}, 200},
		{"new issue missed before requeue", [][3]uint64{{0, 1, 100}, {1, 2, 0}, {0, 2, 200}}, 200},
		{"no allocation timestamp", [][3]uint64{{0, 0, 100}, {1, 0, 0}, {0, 0, 200}}, 0},
		{"unknown allocation reuse is excluded", [][3]uint64{{0, 0, 100}, {1, 0, 0}, {0, 0, 200}, {1, 0, 0}, {0, 0, 300}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := policyFixture(t, 4)
			for _, step := range tc.steps {
				if _, err := runPolicy(c, step[0], step[1], step[2], 0); err != nil {
					t.Fatal(err)
				}
			}
			var got policytestRequestTiming
			if err := c.Maps["timing"].Lookup(uint32(0), &got); err != nil {
				t.Fatal(err)
			}
			if got.Start != tc.wantStart {
				t.Fatalf("first dispatch: got %d, want %d", got.Start, tc.wantStart)
			}
		})
	}
}

func TestCriticalDetailReservation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kinds []uint64
		want  []uint32
	}{
		{"warning first", []uint64{0, 0, 0, 0, 1, 1}, []uint32{1, 1, 1, 0, 1, 0}},
		{"critical first", []uint64{1, 0, 0, 0, 1}, []uint32{1, 1, 1, 0, 1}},
		{"all warning", []uint64{0, 0, 0, 0, 0}, []uint32{1, 1, 1, 0, 0}},
		{"all critical", []uint64{1, 1, 1, 1, 1}, []uint32{1, 1, 1, 1, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := policyFixture(t, 4)
			for i, critical := range tc.kinds {
				got, err := runPolicy(c, 2, 0, 1_000_000_000, critical)
				if err != nil || got != tc.want[i] {
					t.Fatalf("event %d: got %d, want %d, error %v", i, got, tc.want[i], err)
				}
			}
			if got, err := runPolicy(c, 2, 0, 2_000_000_000, 0); err != nil || got != 1 {
				t.Fatalf("new second did not restore quota: %d, %v", got, err)
			}
		})
	}
}

func TestDetailQuotaConcurrentProducers(t *testing.T) {
	c := policyFixture(t, 1000)
	var wg sync.WaitGroup
	errors := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			for range 200 {
				if _, err := runPolicy(c, 2, 0, 1_000_000_000, 0); err != nil {
					errors <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	var budget policytestDetailBudget
	if err := c.Maps["detail_budgets"].Lookup(uint64(1), &budget); err != nil {
		t.Fatal(err)
	}
	// Keep the existing allowance of one in-flight producer per CPU.
	if budget.Used < 750 || budget.Used > 750+8 {
		t.Fatalf("concurrent warnings consumed reserved quota: %d", budget.Used)
	}
	for i := budget.Used; i < 1000; i++ {
		if got, err := runPolicy(c, 2, 0, 1_000_000_000, 1); err != nil || got != 1 {
			t.Fatalf("critical reservation unavailable: %d, %v", got, err)
		}
	}
	if got, err := runPolicy(c, 2, 0, 1_000_000_000, 1); err != nil || got != 0 {
		t.Fatalf("total quota increased: %d, %v", got, err)
	}
}

func TestCompletionRejectsStaleRequestGeneration(t *testing.T) {
	c := policyFixture(t, 4)
	if _, err := runPolicy(c, 0, 1, 100, 0); err != nil {
		t.Fatal(err)
	}
	// Partial completion checks must not consume or restart the original timer.
	for range 2 {
		if got, err := runPolicy(c, 3, 1, 0, 0); err != nil || got != 1 {
			t.Fatal("same allocation rejected", got, err)
		}
	}
	// Both the old completion and the next issue were missed at this address.
	if got, err := runPolicy(c, 3, 2, 0, 0); err != nil || got != 0 {
		t.Fatal("stale allocation accepted", got, err)
	}
	var timing policytestRequestTiming
	if err := c.Maps["timing"].Lookup(uint32(0), &timing); err != nil || timing.Start != 100 {
		t.Fatal("completion check changed first dispatch", timing, err)
	}
}

func TestSmallDetailQuotaReservation(t *testing.T) {
	for _, rate := range []uint32{1, 2, 3, 5} {
		c := policyFixture(t, rate)
		warnLimit := rate - (rate+config.CriticalDetailDivisor-1)/config.CriticalDetailDivisor
		for i := uint32(0); i <= warnLimit; i++ {
			want := uint32(1)
			if i == warnLimit {
				want = 0
			}
			if got, err := runPolicy(c, 2, 0, 1_000_000_000, 0); err != nil || got != want {
				t.Fatalf("rate %d: warning %d returned %d, %v", rate, i, got, err)
			}
		}
		for i := warnLimit; i < rate; i++ {
			if got, err := runPolicy(c, 2, 0, 1_000_000_000, 1); err != nil || got != 1 {
				t.Fatalf("rate %d: reserve unavailable %d, %v", rate, got, err)
			}
		}
	}
}
