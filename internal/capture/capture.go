// Package capture hides the versioned .bbx container implementation.
package capture

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

// Tar framing is part of the storage contract, not an operational setting.
const tarBlockBytes int64 = 512
const tarEndBytes = 2 * tarBlockBytes

type Writer interface {
	Write(io.Writer, model.Capture) error
}
type Reader interface {
	Read(io.Reader) (model.Capture, error)
}
type Container struct{ Limits config.CaptureLimits }

func (c Container) limits() config.CaptureLimits {
	if c.Limits == (config.CaptureLimits{}) {
		return config.Default().Capture
	}
	return c.Limits
}

type footer struct {
	Segments int `json:"segments"`
}

func (container Container) Write(dst io.Writer, c model.Capture) error {
	limits := container.limits()
	if err := limits.Validate(); err != nil {
		return err
	}
	if c.Manifest.FormatVersion != model.FormatVersion {
		return fmt.Errorf("writer requires capture format %d, got %d", model.FormatVersion, c.Manifest.FormatVersion)
	}
	if len(c.Segments) > limits.MaxEntries-3 {
		return fmt.Errorf("too many capture entries")
	}
	z, err := zstd.NewWriter(dst, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderCRC(true), zstd.WithWindowSize(int(limits.CompressionWindowBytes)))
	if err != nil {
		return err
	}
	t := tar.NewWriter(z)
	total := tarEndBytes
	entry := func(name string, v any) error {
		b, e := json.Marshal(v)
		if e != nil {
			return e
		}
		cost := tarBlockBytes + ((int64(len(b))+tarBlockBytes-1)/tarBlockBytes)*tarBlockBytes
		total += cost
		if total > limits.MaxDecodedBytes {
			return fmt.Errorf("capture exceeds decoded size limit")
		}
		if e = t.WriteHeader(&tar.Header{Name: name, Size: int64(len(b)), Mode: 0600}); e != nil {
			return e
		}
		_, e = t.Write(b)
		return e
	}
	if err = entry("manifest.json", c.Manifest); err == nil {
		err = entry("host.json", c.Host)
	}
	// Stream one segment at a time without building a whole-capture blob.
	for i, s := range c.Segments {
		if err != nil {
			break
		}
		err = entry(fmt.Sprintf("segments/%08d.json", i), s)
	}
	if err == nil {
		err = entry("complete.json", footer{len(c.Segments)})
	}
	te := t.Close()
	ze := z.Close()
	if err != nil {
		return err
	}
	if te != nil {
		return te
	}
	return ze
}
func (container Container) Read(src io.Reader) (model.Capture, error) {
	var c model.Capture
	limits := container.limits()
	if err := limits.Validate(); err != nil {
		return c, err
	}
	z, err := zstd.NewReader(src, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(limits.MaxDecodedBytes)))
	if err != nil {
		return c, err
	}
	defer z.Close()
	limited := &io.LimitedReader{R: z, N: limits.MaxDecodedBytes + 1}
	t := tar.NewReader(limited)
	seen := map[string]bool{}
	total := int64(0)
	completed := false
	expected := 0
	for {
		h, e := t.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return c, fmt.Errorf("read capture: %w", e)
		}
		if completed {
			return c, fmt.Errorf("entry after completion marker")
		}
		if h.Typeflag != tar.TypeReg || seen[h.Name] || h.Size < 0 || h.Size > limits.MaxDecodedBytes-total {
			return c, fmt.Errorf("invalid or oversized capture entry %q", h.Name)
		}
		if len(seen) >= limits.MaxEntries {
			return c, fmt.Errorf("too many capture entries")
		}
		if len(seen) == 0 && h.Name != "manifest.json" {
			return c, fmt.Errorf("manifest must be the first capture entry")
		}
		if len(seen) == 1 && h.Name != "host.json" {
			return c, fmt.Errorf("host must follow capture manifest")
		}
		seen[h.Name] = true
		total += h.Size
		b, e := io.ReadAll(io.LimitReader(t, h.Size))
		if e != nil {
			return c, e
		}
		switch h.Name {
		case "manifest.json":
			e = json.Unmarshal(b, &c.Manifest)
			if e == nil {
				e = model.CheckReadableFormat(c.Manifest.FormatVersion)
			}
		case "host.json":
			e = json.Unmarshal(b, &c.Host)
		case "complete.json":
			var f footer
			e = json.Unmarshal(b, &f)
			completed = true
			expected = f.Segments
		default:
			var index int
			if n, _ := fmt.Sscanf(h.Name, "segments/%08d.json", &index); n != 1 || h.Name != fmt.Sprintf("segments/%08d.json", index) {
				return c, fmt.Errorf("unknown capture entry %q", h.Name)
			}
			if index != len(c.Segments) {
				return c, fmt.Errorf("invalid segment sequence")
			}
			var s model.Segment
			e = json.Unmarshal(b, &s)
			c.Segments = append(c.Segments, s)
		}
		if e != nil {
			return c, fmt.Errorf("decode %s: %w", h.Name, e)
		}
	}
	// Drain the decoder to verify the compression trailer and total decoded limit.
	_, err = io.Copy(io.Discard, limited)
	if err != nil {
		return c, err
	}
	if limited.N <= 0 {
		return c, fmt.Errorf("capture exceeds decoded size limit")
	}
	if !completed || expected != len(c.Segments) {
		return c, fmt.Errorf("incomplete capture")
	}
	if !seen["manifest.json"] || !seen["host.json"] {
		return c, fmt.Errorf("capture missing manifest or host")
	}
	if err = model.CheckReadableFormat(c.Manifest.FormatVersion); err != nil {
		return c, err
	}
	if c.Manifest.EndMonoNS < c.Manifest.StartMonoNS || c.Manifest.RequestedStartMonoNS > c.Manifest.StartMonoNS || c.Manifest.RecordingStartMonoNS > c.Manifest.StartMonoNS {
		return c, fmt.Errorf("invalid capture time window")
	}
	for _, s := range c.Segments {
		for _, e := range s.Events {
			if e.MonoNS < c.Manifest.StartMonoNS || e.MonoNS > c.Manifest.EndMonoNS {
				return c, fmt.Errorf("event outside capture window")
			}
		}
		for _, m := range s.Metrics {
			if m.StartMonoNS > m.EndMonoNS || m.StartMonoNS < c.Manifest.StartMonoNS || m.EndMonoNS > c.Manifest.EndMonoNS {
				return c, fmt.Errorf("metric outside capture window")
			}
		}
	}
	return c, nil
}
func ReadFile(path string) (model.Capture, error) {
	return ReadFileWithLimits(path, config.Default().Capture)
}
func ReadFileWithLimits(path string, limits config.CaptureLimits) (model.Capture, error) {
	f, e := os.Open(path)
	if e != nil {
		return model.Capture{}, e
	}
	defer f.Close()
	return (Container{Limits: limits}).Read(f)
}

// Publish creates a private file atomically and refuses to overwrite an incident.
func Publish(path string, write func(io.Writer) error) error {
	return PublishWithLimits(path, config.Default().Capture, write)
}
func PublishWithLimits(path string, limits config.CaptureLimits, write func(io.Writer) error) error {
	dir := filepath.Dir(path)
	f, e := os.CreateTemp(dir, ".blackbox-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if e = f.Chmod(0600); e != nil {
		return e
	}
	if e = write(f); e != nil {
		return e
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return e
	}
	if _, e = (Container{Limits: limits}).Read(f); e != nil {
		return fmt.Errorf("validate capture before publication: %w", e)
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Link(f.Name(), path); e != nil {
		return fmt.Errorf("publish capture (destination must not exist): %w", e)
	}
	return nil
}
func WriteFile(path string, c model.Capture) error {
	return WriteFileWithLimits(path, c, config.Default().Capture)
}

func WriteFileWithLimits(path string, c model.Capture, limits config.CaptureLimits) error {
	return PublishWithLimits(path, limits, func(w io.Writer) error { return (Container{Limits: limits}).Write(w, c) })
}
