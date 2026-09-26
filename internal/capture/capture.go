// Package capture hides the versioned .bbx container implementation.
package capture

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
		entry := &io.LimitedReader{R: t, N: h.Size}
		decoder := json.NewDecoder(entry)
		switch h.Name {
		case "manifest.json":
			e = decoder.Decode(&c.Manifest)
			if e == nil {
				e = model.CheckReadableFormat(c.Manifest.FormatVersion)
			}
		case "host.json":
			e = decoder.Decode(&c.Host)
		case "complete.json":
			var f footer
			e = decoder.Decode(&f)
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
			s, e = decodeSegment(decoder)
			c.Segments = append(c.Segments, s)
		}
		if e != nil {
			return c, fmt.Errorf("decode %s: %w", h.Name, e)
		}
		if e = consumeJSONTail(decoder, entry); e != nil {
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
	if !c.Manifest.AutoIncident.Valid(c.Manifest.EndMonoNS) {
		return c, fmt.Errorf("invalid automatic incident metadata")
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

// Decode large segments one observation at a time instead of retaining their
// entire JSON entry alongside the resulting event and metric slices.
func decodeSegment(decoder *json.Decoder) (model.Segment, error) {
	var segment model.Segment
	start, err := decoder.Token()
	if err != nil || start == nil {
		return segment, err
	}
	if start != json.Delim('{') {
		return segment, fmt.Errorf("segment must be a JSON object")
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return segment, err
		}
		switch name := key.(string); {
		case strings.EqualFold(name, "start_mono_ns"):
			err = decoder.Decode(&segment.StartMonoNS)
		case strings.EqualFold(name, "end_mono_ns"):
			err = decoder.Decode(&segment.EndMonoNS)
		case strings.EqualFold(name, "events"):
			segment.Events, err = decodeArray[model.Event](decoder)
		case strings.EqualFold(name, "metrics"):
			segment.Metrics, err = decodeArray[model.Metric](decoder)
		default:
			err = skipJSONValue(decoder)
		}
		if err != nil {
			return segment, err
		}
	}
	end, err := decoder.Token()
	if err != nil {
		return segment, err
	}
	if end != json.Delim('}') {
		return segment, fmt.Errorf("invalid segment object ending")
	}
	return segment, nil
}

func decodeArray[T any](decoder *json.Decoder) ([]T, error) {
	start, err := decoder.Token()
	if err != nil || start == nil {
		return nil, err
	}
	if start != json.Delim('[') {
		return nil, fmt.Errorf("expected JSON array")
	}
	values := make([]T, 0)
	for decoder.More() {
		var value T
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	end, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if end != json.Delim(']') {
		return nil, fmt.Errorf("invalid JSON array ending")
	}
	return values, nil
}

func skipJSONValue(decoder *json.Decoder) error {
	value, err := decoder.Token()
	if err != nil {
		return err
	}
	depth := 0
	if delim, ok := value.(json.Delim); ok && (delim == '{' || delim == '[') {
		depth = 1
	}
	for depth > 0 {
		value, err = decoder.Token()
		if err != nil {
			return err
		}
		if delim, ok := value.(json.Delim); ok {
			switch delim {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

func consumeJSONTail(decoder *json.Decoder, entry *io.LimitedReader) error {
	tail := io.MultiReader(decoder.Buffered(), entry)
	var buffer [4096]byte
	for {
		n, err := tail.Read(buffer[:])
		for _, b := range buffer[:n] {
			if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
				return fmt.Errorf("entry contains trailing JSON data")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if entry.N != 0 {
		return io.ErrUnexpectedEOF
	}
	return nil
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
	return PublishWithContext(context.Background(), path, limits, write)
}

// PublishWithContext aborts an in-progress write or validation on cancellation.
func PublishWithContext(ctx context.Context, path string, limits config.CaptureLimits, write func(io.Writer) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
	if e = write(contextWriter{ctx, f}); e != nil {
		return e
	}
	directory, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer directory.Close()
	e = finishPublication(ctx, f, directory, limits, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return os.Link(f.Name(), path)
	})
	if e != nil {
		return fmt.Errorf("capture %s: %w", path, e)
	}
	return nil
}

// PublishInRootWithLimits keeps automatic publication inside an already opened,
// private directory. name must be unique; its partial file is exclusively created.
func PublishInRootWithLimits(ctx context.Context, root *os.Root, name string, limits config.CaptureLimits, write func(io.Writer) error) error {
	if filepath.Base(name) != name {
		return fmt.Errorf("capture name must not contain a directory")
	}
	temp := "." + name + ".partial"
	f, err := root.OpenFile(temp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	defer f.Close()
	if err = write(f); err != nil {
		return err
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return finishPublication(ctx, f, directory, limits, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return root.Link(temp, name)
	})
}

func finishPublication(ctx context.Context, f, directory *os.File, limits config.CaptureLimits, publish func() error) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := (Container{Limits: limits}).Read(contextReader{ctx, f}); err != nil {
		return fmt.Errorf("validate capture before publication: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := publish(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("publish capture (destination must not exist): %w", err)
	}
	// Sync the new name, not only the file contents, before claiming it was saved.
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync capture directory after publication (destination may exist): %w", err)
	}
	return nil
}

func WriteFile(path string, c model.Capture) error {
	return WriteFileWithLimits(path, c, config.Default().Capture)
}

func WriteFileWithLimits(path string, c model.Capture, limits config.CaptureLimits) error {
	return PublishWithLimits(path, limits, func(w io.Writer) error { return (Container{Limits: limits}).Write(w, c) })
}

// Validation of an automatic file shares the encoding deadline. The underlying
// filesystem syscall itself cannot be interrupted while blocked in the kernel.
type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

type contextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (w contextWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.writer.Write(p)
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
