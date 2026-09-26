package capture

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// BenchmarkCaptureDecode measures a large existing-format segment. The archive
// is built outside the timed loop and is independent of the current writer.
func BenchmarkCaptureDecode(b *testing.B) {
	const events = 200000
	archive, segmentBytes := benchmarkFormatOneArchive(b, events)
	b.SetBytes(segmentBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoded, err := (Container{}).Read(bytes.NewReader(archive))
		if err != nil {
			b.Fatal(err)
		}
		if len(decoded.Segments) != 1 || len(decoded.Segments[0].Events) != events {
			b.Fatalf("decoded %d events, want %d", len(decoded.Segments[0].Events), events)
		}
		runtime.KeepAlive(decoded)
	}
	b.StopTimer()
	b.ReportMetric(float64(events), "events/op")
	b.ReportMetric(float64(len(archive))/1048576, "compressedMiB")
}

func benchmarkFormatOneArchive(b *testing.B, count int) ([]byte, int64) {
	b.Helper()
	var archive bytes.Buffer
	z, err := zstd.NewWriter(&archive, zstd.WithEncoderConcurrency(1))
	if err != nil {
		b.Fatal(err)
	}
	tw := tar.NewWriter(z)
	write := func(name string, body []byte) {
		b.Helper()
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body))}); err != nil {
			b.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			b.Fatal(err)
		}
	}
	for _, name := range []string{"manifest.json", "host.json"} {
		body, err := os.ReadFile(filepath.Join("testdata", "v1", name))
		if err != nil {
			b.Fatal(err)
		}
		write(name, body)
	}
	const prefix = `{"start_mono_ns":10,"end_mono_ns":20,"events":[`
	const suffix = `],"metrics":[]}`
	event := []byte(`{"mono_ns":15,"type":"oom","pid":42,"comm":"worker000000"}`)
	segmentBytes := int64(len(prefix) + len(suffix) + count*len(event) + count - 1)
	if err := tw.WriteHeader(&tar.Header{Name: "segments/00000000.json", Mode: 0600, Size: segmentBytes}); err != nil {
		b.Fatal(err)
	}
	if _, err := tw.Write([]byte(prefix)); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < count; i++ {
		if i > 0 {
			if _, err := tw.Write([]byte{','}); err != nil {
				b.Fatal(err)
			}
		}
		for n, value := 5, i; n >= 0; n, value = n-1, value/10 {
			event[len(event)-8+n] = byte('0' + value%10)
		}
		if _, err := tw.Write(event); err != nil {
			b.Fatal(err)
		}
	}
	if _, err := tw.Write([]byte(suffix)); err != nil {
		b.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join("testdata", "v1", "complete.json"))
	if err != nil {
		b.Fatal(err)
	}
	write("complete.json", body)
	if err := tw.Close(); err != nil {
		b.Fatal(err)
	}
	if err := z.Close(); err != nil {
		b.Fatal(err)
	}
	if archive.Len() == 0 {
		b.Fatal("empty benchmark archive")
	}
	return archive.Bytes(), segmentBytes
}
