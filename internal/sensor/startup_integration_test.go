//go:build linux && integration

package sensor

import (
	"strings"
	"testing"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
)

func TestUnavailableSensorDefaultStrictAndDisabled(t *testing.T) {
	defs := definitions(config.Default())
	for i := range defs {
		if defs[i].name == "oom" {
			defs[i].hooks = map[string]string{"victim": "blackbox_intentionally_absent_hook"}
		}
	}
	for _, mode := range []string{"best-effort", "strict", "disabled-strict"} {
		t.Run(mode, func(t *testing.T) {
			c := config.Default()
			c.Strict = mode != "best-effort"
			if mode == "disabled-strict" {
				c.Enabled = []string{"block_io", "scheduler", "tcp"}
			}
			ss, missing, err := openDefinitions(c, defs)
			defer func() {
				for _, s := range ss {
					_ = s.Close()
				}
			}()
			if mode == "strict" {
				if err == nil || !strings.Contains(err.Error(), "strict mode") || len(ss) != 0 {
					t.Fatalf("strict initialization did not fail: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(ss) != 3 {
				t.Fatalf("remaining sensors=%d", len(ss))
			}
			if len(missing) != 1 || missing[0].Name != "oom" {
				t.Fatal(missing)
			}
			state := "unavailable"
			if mode == "disabled-strict" {
				state = "disabled"
			}
			if missing[0].State != state || missing[0].Reason == "" {
				t.Fatal(missing)
			}
		})
	}
}
