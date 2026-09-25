package autocapture

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/capture"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

func recording() model.Capture {
	return model.Capture{Manifest: model.Manifest{FormatVersion: model.FormatVersion, StartMonoNS: seconds(40), RequestedStartMonoNS: seconds(40), EndMonoNS: seconds(110), AutoIncident: &model.AutoIncident{DetectedMonoNS: seconds(100), EndMonoNS: seconds(110), BeforeNS: seconds(60), AfterNS: seconds(10), Triggers: []model.AutoTrigger{{Family: "oom", Reason: "oom_victim", Count: 1, FirstIntervalStartNS: seconds(99), LastIntervalEndNS: seconds(100)}}}}}
}
func storeFor(t *testing.T) Store {
	t.Helper()
	c := config.Default()
	c.AutoCapture.Directory = filepath.Join(t.TempDir(), "auto")
	return Store{Config: c}
}
func managed(t *testing.T, path string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	var files []os.DirEntry
	for _, e := range entries {
		if automaticName.MatchString(e.Name()) {
			files = append(files, e)
		}
		if strings.HasSuffix(e.Name(), ".partial") {
			t.Fatalf("orphaned partial: %s", e.Name())
		}
	}
	return files
}

func TestStorageRotatesOldestWithinBothLimitsAndSurvivesRestart(t *testing.T) {
	for _, limit := range []string{"files", "bytes", "both"} {
		t.Run(limit, func(t *testing.T) {
			s := storeFor(t)
			first, err := s.Save(context.Background(), recording())
			if err != nil {
				t.Fatal(err)
			}
			info, _ := os.Stat(first)
			if info.Mode().Perm() != 0600 {
				t.Fatal("public capture permissions")
			}
			if limit != "bytes" {
				s.Config.AutoCapture.MaxFiles = 2
			}
			if limit != "files" {
				s.Config.AutoCapture.MaxStorage = 2 * info.Size()
			}
			manual := filepath.Join(s.Config.AutoCapture.Directory, "incident.bbx")
			if err = os.WriteFile(manual, []byte("manual evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			// Distinct mtime makes the expected rotation order explicit.
			if err = os.Chtimes(first, time.Unix(1, 0), time.Unix(1, 0)); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				restarted := Store{Config: s.Config}
				path, err := restarted.Save(context.Background(), recording())
				if err != nil {
					t.Fatal(err)
				}
				if _, err = capture.ReadFile(path); err != nil {
					t.Fatal(err)
				}
			}
			files := managed(t, s.Config.AutoCapture.Directory)
			var total int64
			for _, f := range files {
				st, _ := f.Info()
				total += st.Size()
			}
			if len(files) != 2 || total > s.Config.AutoCapture.MaxStorage {
				t.Fatalf("quota: files=%d bytes=%d", len(files), total)
			}
			if _, err := os.Stat(first); !os.IsNotExist(err) {
				t.Fatal("oldest capture remains", err)
			}
			if b, err := os.ReadFile(manual); err != nil || string(b) != "manual evidence" {
				t.Fatal("manual capture modified")
			}
		})
	}
}

func TestStorageFailuresAndCrashRecovery(t *testing.T) {
	t.Run("cancelled", func(t *testing.T) {
		s := storeFor(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := s.Save(ctx, recording()); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if _, err := os.Stat(s.Config.AutoCapture.Directory); !os.IsNotExist(err) {
			t.Fatal("cancelled write created storage")
		}
	})
	t.Run("unwritable destination", func(t *testing.T) {
		s := storeFor(t)
		if err := os.WriteFile(s.Config.AutoCapture.Directory, []byte("occupied"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Save(context.Background(), recording()); err == nil {
			t.Fatal("accepted file as directory")
		}
	})
	t.Run("private directory", func(t *testing.T) {
		s := storeFor(t)
		if err := os.Mkdir(s.Config.AutoCapture.Directory, 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Save(context.Background(), recording()); err == nil {
			t.Fatal("accepted public directory")
		}
	})
	t.Run("oversized single capture", func(t *testing.T) {
		s := storeFor(t)
		s.Config.AutoCapture.MaxStorage = 1
		if _, err := s.Save(context.Background(), recording()); err == nil {
			t.Fatal("accepted oversized capture")
		}
		if len(managed(t, s.Config.AutoCapture.Directory)) != 0 {
			t.Fatal("partial published")
		}
	})
	t.Run("failed replacement preserves old capture", func(t *testing.T) {
		s := storeFor(t)
		old, err := s.Save(context.Background(), recording())
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(old)
		if err != nil {
			t.Fatal(err)
		}
		s.Config.AutoCapture.MaxFiles = 1
		s.Config.AutoCapture.MaxStorage = info.Size()
		s.Config.Control.MaxCaptureBytes = info.Size() - 1
		if _, err := s.Save(context.Background(), recording()); err == nil {
			t.Fatal("accepted replacement over the single-file budget")
		}
		if _, err := capture.ReadFile(old); err != nil || len(managed(t, s.Config.AutoCapture.Directory)) != 1 {
			t.Fatal("failed replacement removed old evidence", err)
		}
	})
	t.Run("stale partial", func(t *testing.T) {
		s := storeFor(t)
		path, err := s.Save(context.Background(), recording())
		if err != nil {
			t.Fatal(err)
		}
		partial := filepath.Join(s.Config.AutoCapture.Directory, "."+filepath.Base(path)+".partial")
		if err := os.WriteFile(partial, []byte("crashed write"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Save(context.Background(), recording()); err != nil {
			t.Fatal(err)
		}
		managed(t, s.Config.AutoCapture.Directory)
	})
	t.Run("managed symlink", func(t *testing.T) {
		s := storeFor(t)
		path, err := s.Save(context.Background(), recording())
		if err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "evidence")
		os.WriteFile(outside, []byte("keep"), 0600)
		os.Remove(path)
		if err = os.Symlink(outside, path); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Save(context.Background(), recording()); err == nil {
			t.Fatal("accepted managed symlink")
		}
		if b, _ := os.ReadFile(outside); string(b) != "keep" {
			t.Fatal("outside file changed")
		}
	})
}

func TestSharedDirectoryLock(t *testing.T) {
	s := storeFor(t)
	if _, err := s.Save(context.Background(), recording()); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(s.Config.AutoCapture.Directory, ".lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = lockDirectory(lock); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Save(context.Background(), recording()); err == nil {
		t.Fatal("concurrent directory writer accepted")
	}
	lock.Close()
	if _, err = s.Save(context.Background(), recording()); err != nil {
		t.Fatal(err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrShortWrite }
func TestStorageAccountsTemporaryBytesAndWriteFailures(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fd, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	var dst bytes.Buffer
	w := storageWriter{ctx: context.Background(), dir: fd, dst: &dst, maxFile: 8}
	if _, err = w.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if w.written != 4 {
		t.Fatal("temporary bytes not counted")
	}
	if _, err = w.Write([]byte("56789")); err == nil || dst.Len() != 4 {
		t.Fatal("single-file cap not enforced before write")
	}
	w.dst = failingWriter{}
	if _, err = w.Write([]byte("a")); !errors.Is(err, io.ErrShortWrite) || w.written != 4 {
		t.Fatal("write failure hidden or counted", err)
	}
}

func TestFreeSpaceGuardAndFilesystemFailure(t *testing.T) {
	w := storageWriter{ctx: context.Background(), dst: &bytes.Buffer{}, maxFile: 100, available: func(*os.File) (uint64, error) { return uint64(config.AutoMinFreeBytes), nil }}
	if _, err := w.Write([]byte("x")); err == nil || !strings.Contains(err.Error(), "insufficient free space") {
		t.Fatal("free-space guard failed", err)
	}
	if w.written != 0 {
		t.Fatal("space failure consumed budget")
	}
	w.available = func(*os.File) (uint64, error) { return 0, os.ErrPermission }
	if _, err := w.Write([]byte("x")); !errors.Is(err, os.ErrPermission) {
		t.Fatal("statfs failure hidden", err)
	}
}

func TestLowFreeSpacePreservesOldAutomaticFile(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fd, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	name := "blackbox-auto-20260925T000000Z-0123456789abcdef.bbx"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	var dst bytes.Buffer
	w := storageWriter{ctx: context.Background(), dir: fd, dst: &dst, maxFile: 100, available: func(*os.File) (uint64, error) { return uint64(config.AutoMinFreeBytes), nil }}
	if _, err := w.Write([]byte("new")); err == nil {
		t.Fatal("staged capture without free-space reserve")
	}
	if old, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(old) != "old" || dst.Len() != 0 {
		t.Fatal("low-space failure removed old capture", err)
	}
}
