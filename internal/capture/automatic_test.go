package capture

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
)

func TestRootedPublicationCancellationAndOverwrite(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	write := func(w io.Writer) error { return (Container{}).Write(w, sample()) }
	if err = PublishInRootWithLimits(context.Background(), root, "saved.bbx", config.Default().Capture, write); err != nil {
		t.Fatal(err)
	}
	original, err := root.ReadFile("saved.bbx")
	if err != nil {
		t.Fatal(err)
	}
	if err = PublishInRootWithLimits(context.Background(), root, "saved.bbx", config.Default().Capture, write); err == nil {
		t.Fatal("overwrote capture")
	}
	now, err := root.ReadFile("saved.bbx")
	if err != nil || string(now) != string(original) {
		t.Fatal("existing capture changed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	err = PublishInRootWithLimits(ctx, root, "cancelled.bbx", config.Default().Capture, func(w io.Writer) error { err := write(w); cancel(); return err })
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled validation published", err)
	}
	for _, name := range []string{"cancelled.bbx", ".cancelled.bbx.partial", ".saved.bbx.partial"} {
		if _, err := root.Stat(name); !os.IsNotExist(err) {
			t.Fatal("unexpected file", name, err)
		}
	}
	if err = PublishInRootWithLimits(context.Background(), root, "../escape.bbx", config.Default().Capture, write); err == nil {
		t.Fatal("relative escape accepted")
	}
}

func TestManualPublicationCancellationLeavesNoCapture(t *testing.T) {
	for _, stage := range []string{"during write", "before validation"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dir := t.TempDir()
			path := filepath.Join(dir, "incident.bbx")
			err := PublishWithContext(ctx, path, config.Default().Capture, func(w io.Writer) error {
				if stage == "during write" {
					cancel()
					_, err := w.Write([]byte("never published"))
					return err
				}
				if err := (Container{}).Write(w, sample()); err != nil {
					return err
				}
				cancel()
				return nil
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled capture was accepted: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("partial or final capture remains: %v %v", entries, err)
			}
		})
	}
}

func TestPublicationRequiresDirectorySync(t *testing.T) {
	dir := t.TempDir()
	temp, err := os.CreateTemp(dir, ".blackbox-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp.Name())
	if err := (Container{}).Write(temp, sample()); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "incident.bbx")
	err = finishPublication(context.Background(), temp, directory, config.Default().Capture, func() error {
		return os.Link(temp.Name(), path)
	})
	if err == nil || !strings.Contains(err.Error(), "sync capture directory") {
		t.Fatalf("directory sync failure was reported as a saved capture: %v", err)
	}
	if _, err := ReadFile(path); err != nil {
		t.Fatal("published capture disappeared on sync error", err)
	}
}
