package config

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultsIndependentAndValid(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Enabled[0] = "changed"
	if Default().Enabled[0] == "changed" {
		t.Fatal("default sensor list aliases mutable state")
	}
}
func TestInvalidResourceBudgets(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"history", func(c *Config) { c.History = 0 }}, {"relative socket", func(c *Config) { c.Socket = "local.sock" }},
		{"memory", func(c *Config) { c.MaxMemory = MaxMemory + 1 }}, {"duplicate sensor", func(c *Config) { c.Enabled = []string{"tcp", "tcp"} }},
		{"empty sensor", func(c *Config) { c.Enabled = nil }}, {"ingress", func(c *Config) { c.Resources.IngressEvents = 0 }},
		{"metadata path", func(c *Config) { c.Resources.MetadataPathBytes = MaxMetadataPathBytes + 1 }},
		{"ring", func(c *Config) { c.Resources.RingBytes = MinRingBytes + 1 }}, {"tracking", func(c *Config) { c.Resources.BlockTrackingEntries = 0 }},
		{"poll", func(c *Config) { c.Resources.PollInterval = 0 }}, {"segment exceeds history", func(c *Config) { c.History = time.Second; c.Resources.SegmentInterval = 2 * time.Second }},
		{"clients", func(c *Config) { c.Control.MaxClients = 0 }}, {"query timeout", func(c *Config) { c.Control.QueryTimeout = c.Control.Timeout + time.Second }},
		{"compression window", func(c *Config) { c.Capture.CompressionWindowBytes = MinCompressionWindowBytes + 1 }},
		{"compression exceeds decoded budget", func(c *Config) { c.Capture.MaxDecodedBytes = MinMemory; c.Capture.CompressionWindowBytes = 2 << 20 }},
		{"capture entries", func(c *Config) { c.Capture.MaxEntries = 2 }}, {"capture transport smaller than decode", func(c *Config) { c.Control.MaxCaptureBytes = MinMemory }},
		{"auto write timeout", func(c *Config) { c.AutoCapture.WriteTimeout = 0 }},
		{"report", func(c *Config) { c.Report.Events = 0 }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := Default()
			tt.mutate(&c)
			if c.Validate() == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}
func TestMemoryUnitsOverflowAndRoundTrip(t *testing.T) {
	for _, s := range []string{"1B", "64KiB", "32MiB", "1GiB"} {
		n, err := Memory(s)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Memory(MemoryText(n))
		if err != nil || n != again {
			t.Fatal("byte quantity changed")
		}
	}
	for _, s := range []string{"-1MiB", "1.5MiB", "32MB", "9223372036854775807GiB", strings.Repeat("9", 100) + "B"} {
		if _, err := Memory(s); err == nil {
			t.Fatalf("invalid quantity accepted: %q", s)
		}
	}
}
