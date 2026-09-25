package capture

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

// Raw fixtures deliberately bypass the current writer. Old fields and producer
// versions must keep their meaning even as new optional fields are added.
func legacyArchive(t *testing.T, names []string) []byte {
	t.Helper()
	var b bytes.Buffer
	z, err := zstd.NewWriter(&b, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(z)
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join("testdata", "v1", filepath.Base(name)))
		if err != nil {
			t.Fatal(err)
		}
		if err = tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err = tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestLegacyV1FixtureAndAdditiveFields(t *testing.T) {
	b := legacyArchive(t, []string{"manifest.json", "host.json", "segments/00000000.json", "complete.json"})
	c, err := (Container{}).Read(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if c.Manifest.ApplicationVersion != "0.1.0-legacy-fixture" || c.Manifest.RecordingStartMonoNS != 0 || c.Manifest.Settings.PollIntervalNS != 0 {
		t.Fatal("legacy capture was reinterpreted")
	}
	e := c.Segments[0].Events[0]
	if e.TCPDirection != "" || e.EndpointSource != "" || e.SocketContext != "" || e.SourceIP != "127.0.0.1" {
		t.Fatal("legacy reset direction/provenance invented")
	}
}
func TestCaptureOrderAndIndependentLimits(t *testing.T) {
	for _, names := range [][]string{
		{"host.json", "manifest.json", "segments/00000000.json", "complete.json"},
		{"manifest.json", "segments/00000000.json", "host.json", "complete.json"},
		{"manifest.json", "host.json", "complete.json", "segments/00000000.json"},
	} {
		if _, err := (Container{}).Read(bytes.NewReader(legacyArchive(t, names))); err == nil {
			t.Fatal("invalid entry order accepted")
		}
	}
	c := sample()
	limits := config.Default().Capture
	limits.MaxEntries = 3
	if err := (Container{Limits: limits}).Write(&bytes.Buffer{}, c); err == nil {
		t.Fatal("writer ignored entry budget")
	}
	b := legacyArchive(t, []string{"manifest.json", "host.json", "segments/00000000.json", "complete.json"})
	if _, err := (Container{Limits: limits}).Read(bytes.NewReader(b)); err == nil {
		t.Fatal("reader ignored entry budget")
	}
	c.Segments[0].Events[0].Comm = strings.Repeat("x", int(config.MinMemory)+1)
	limits = config.Default().Capture
	limits.MaxDecodedBytes = config.MinMemory
	if err := (Container{Limits: limits}).Write(&bytes.Buffer{}, c); err == nil {
		t.Fatal("writer ignored decoded size budget")
	}
}
func TestUnsupportedFormatHasActionableTypedError(t *testing.T) {
	// Name the deliberately future manifest correctly, without using the writer.
	var out bytes.Buffer
	z, _ := zstd.NewWriter(&out)
	tw := tar.NewWriter(z)
	body, _ := os.ReadFile("testdata/v1/future-manifest.json")
	tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(body))})
	tw.Write(body)
	tw.Close()
	z.Close()
	_, err := (Container{}).Read(&out)
	var unsupported *model.UnsupportedFormatError
	if !errors.As(err, &unsupported) || unsupported.Found != 999 || !strings.Contains(err.Error(), "compatible analyzer") {
		t.Fatalf("error=%v", err)
	}
}
func TestChecksumCorruptionCannotBePublished(t *testing.T) {
	var b bytes.Buffer
	if err := (Container{}).Write(&b, sample()); err != nil {
		t.Fatal(err)
	}
	data := append([]byte(nil), b.Bytes()...)
	data[len(data)-1] ^= 0xff
	path := filepath.Join(t.TempDir(), "corrupt.bbx")
	if err := Publish(path, func(w io.Writer) error { _, err := w.Write(data); return err }); err == nil {
		t.Fatal("corrupt capture published")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("corrupt capture left a destination")
	}
	if _, err := (Container{}).Read(bytes.NewReader(data)); err == nil {
		t.Fatal("corrupt checksum accepted")
	}
}
func FuzzContainerRead(f *testing.F) {
	var b bytes.Buffer
	if err := (Container{}).Write(&b, sample()); err != nil {
		f.Fatal(err)
	}
	f.Add(b.Bytes())
	f.Add([]byte("not a capture"))
	f.Add([]byte{})
	limits := config.Default().Capture
	limits.MaxDecodedBytes = 4 << 20
	limits.MaxEntries = 128
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4<<20 {
			t.Skip()
		}
		_, _ = (Container{Limits: limits}).Read(bytes.NewReader(data))
	})
}

func TestValidCapturesCanUseMinimumDecodedBudget(t *testing.T) {
	for _, events := range []int{1, 500} {
		t.Run(fmt.Sprint(events), func(t *testing.T) {
			limits := config.Default().Capture
			limits.MaxDecodedBytes = config.MinMemory
			c := sample()
			c.Segments[0].Events = make([]model.Event, events)
			for i := range c.Segments[0].Events {
				c.Segments[0].Events[i] = model.Event{MonoNS: 15, Type: "oom", PID: uint32(i + 1), Comm: "fixture", CgroupPath: strings.Repeat("g", 1024)}
			}
			path := filepath.Join(t.TempDir(), "small.bbx")
			if err := WriteFileWithLimits(path, c, limits); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadFileWithLimits(path, limits); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAutomaticMetadataRoundTripAndValidation(t *testing.T) {
	c := sample()
	c.Manifest.AutoIncident = &model.AutoIncident{DetectedMonoNS: 15, EndMonoNS: 20, BeforeNS: 5, AfterNS: 5, Triggers: []model.AutoTrigger{{Family: "oom", Reason: "oom_victim", Count: 1, FirstIntervalStartNS: 10, LastIntervalEndNS: 15}}}
	var b bytes.Buffer
	if err := (Container{}).Write(&b, c); err != nil {
		t.Fatal(err)
	}
	got, err := (Container{}).Read(&b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest.FormatVersion != model.FormatVersion || got.Manifest.AutoIncident.Triggers[0].Count != 1 {
		t.Fatal("optional metadata changed format")
	}
	for _, mutate := range []func(*model.AutoIncident){
		func(a *model.AutoIncident) { a.AfterNS++ },
		func(a *model.AutoIncident) { a.Triggers = append(a.Triggers, a.Triggers[0]) },
		func(a *model.AutoIncident) { a.Triggers[0].Family = "tcp" },
		func(a *model.AutoIncident) { a.Triggers[0].Count = 0 },
		func(a *model.AutoIncident) { a.EndMonoNS = 21 },
	} {
		clone := *c.Manifest.AutoIncident
		clone.Triggers = append([]model.AutoTrigger(nil), clone.Triggers...)
		mutate(&clone)
		bad := c
		bad.Manifest.AutoIncident = &clone
		b.Reset()
		if err := (Container{}).Write(&b, bad); err != nil {
			t.Fatal(err)
		}
		if _, err := (Container{}).Read(&b); err == nil {
			t.Fatal("invalid automatic metadata accepted")
		}
	}
}
