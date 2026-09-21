package capture

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func sample() model.Capture {
	return model.Capture{Manifest: model.Manifest{FormatVersion: 1, StartMonoNS: 10, EndMonoNS: 20, Mode: "test"}, Host: model.Host{Hostname: "test"}, Segments: []model.Segment{{StartMonoNS: 10, EndMonoNS: 20, Events: []model.Event{{MonoNS: 15, Type: "oom", PID: 42}}}}}
}
func TestRoundTripPrivatePublicationNoOverwrite(t *testing.T) {
	c := sample()
	c.Manifest.RecordingStartMonoNS = 5
	c.Manifest.Health.Sensors = []model.SensorHealth{{Name: "block_io", State: "healthy", BookkeepingCompletions: 64}}
	c.Segments[0].Metrics = []model.Metric{{Family: "block_io", StartMonoNS: 10, EndMonoNS: 20, BookkeepingCompletions: 32}}
	c.Segments[0].Events = append(c.Segments[0].Events, model.Event{MonoNS: 16, Type: "tcp_reset", SourceIP: "127.0.0.1", DestinationIP: "127.0.0.1", SourcePort: 49881, DestinationPort: 37677, TCPDirection: "sent", SocketContext: "none", EndpointSource: "packet_header"})
	path := filepath.Join(t.TempDir(), "incident.bbx")
	if e := WriteFile(path, c); e != nil {
		t.Fatal(e)
	}
	s, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	if s.Mode().Perm() != 0600 {
		t.Fatal(s.Mode())
	}
	got, e := ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	before, _ := os.ReadFile(path)
	if e = WriteFile(path, c); e == nil {
		t.Fatal("overwrite accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("original incident changed")
	}
}
func TestRejectTruncationFutureVersionAndOutOfWindow(t *testing.T) {
	for _, variant := range []string{"truncated", "version", "window", "startup", "requested-start"} {
		t.Run(variant, func(t *testing.T) {
			c := sample()
			if variant == "version" {
				c.Manifest.FormatVersion = 999
			}
			if variant == "window" {
				c.Segments[0].Events[0].MonoNS = 21
			}
			if variant == "startup" {
				c.Manifest.RecordingStartMonoNS = 11
			}
			if variant == "requested-start" {
				c.Manifest.RequestedStartMonoNS = 11
			}
			var b bytes.Buffer
			if e := (Container{}).Write(&b, c); e != nil {
				if variant == "version" {
					return
				}
				t.Fatal(e)
			}
			data := b.Bytes()
			if variant == "truncated" {
				data = data[:len(data)-5]
			}
			if _, e := (Container{}).Read(bytes.NewReader(data)); e == nil {
				t.Fatal("invalid capture accepted")
			}
		})
	}
}
func TestRejectMissingCompletionAndDuplicateEntries(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		var b bytes.Buffer
		z, _ := zstd.NewWriter(&b)
		tw := tar.NewWriter(z)
		body, _ := json.Marshal(sample().Manifest)
		n := 1
		if duplicate {
			n = 2
		}
		for i := 0; i < n; i++ {
			_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(body))})
			_, _ = tw.Write(body)
		}
		_ = tw.Close()
		_ = z.Close()
		if _, e := (Container{}).Read(&b); e == nil {
			t.Fatal("incomplete/duplicate container accepted")
		}
	}
}
func TestFailedPublicationLeavesNoIncident(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.bbx")
	if e := Publish(path, func(w io.Writer) error { _, e := w.Write([]byte("truncated")); return e }); e == nil {
		t.Fatal("bad capture published")
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("partial incident exists")
	}
}
