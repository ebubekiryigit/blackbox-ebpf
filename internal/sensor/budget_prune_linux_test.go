//go:build linux

package sensor

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func TestBudgetPruneFailurePolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cause     error
		retryable bool
	}{
		{"interrupted iteration", unix.EINTR, true},
		{"temporarily unavailable", unix.EAGAIN, true},
		{"closed map", unix.EBADF, false},
		{"missing map", errors.New("detail budget map is missing"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &kernelSensor{health: model.SensorHealth{Name: "scheduler", State: "healthy"}}
			failure := fmt.Errorf("iterate detail budgets: %w", tc.cause)
			for i := 0; i < 2; i++ {
				err := s.handleBudgetPruneError(failure)
				if tc.retryable && err != nil || !tc.retryable && !errors.Is(err, tc.cause) {
					t.Fatalf("unexpected cleanup error: %v", err)
				}
			}
			h := s.Health()
			if tc.retryable {
				if h.State != "healthy" || h.BudgetPruneFailures != 2 || s.lastBudgetSweepSec != 0 {
					t.Fatalf("transient cleanup error disabled aggregation or advanced sweep: %+v", h)
				}
			} else if h.State != "error" || h.BudgetPruneFailures != 0 || h.Reason == "" {
				t.Fatalf("permanent cleanup error was hidden: %+v", h)
			}
		})
	}
}
