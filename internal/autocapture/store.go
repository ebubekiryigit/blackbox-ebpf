package autocapture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ebubekiryigit/blackbox-ebpf/internal/capture"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/config"
	"github.com/ebubekiryigit/blackbox-ebpf/internal/model"
)

var automaticName = regexp.MustCompile(`^blackbox-auto-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\.bbx$`)

type storedFile struct {
	name     string
	size     int64
	modified time.Time
}

type Store struct{ Config config.Config }

// Save serializes directory ownership, rotation and publication across daemons.
// No directory traversal or filesystem work runs on the recorder's goroutine.
func (s Store) Save(ctx context.Context, c model.Capture) (string, error) {
	return s.save(ctx, c, rotate)
}

type rotateFiles func(*os.Root, *os.File, []storedFile, int64, int64, int, config.AutoCapture) ([]storedFile, int64, error)

func (s Store) save(ctx context.Context, c model.Capture, rotateFn rotateFiles) (string, error) {
	a := s.Config.AutoCapture
	if c.Manifest.AutoIncident == nil || !c.Manifest.AutoIncident.Valid(c.Manifest.EndMonoNS) {
		return "", fmt.Errorf("automatic capture requires trigger metadata")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := os.MkdirAll(a.Directory, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(a.Directory)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("automatic capture directory must be private (0700), not a symlink")
	}
	root, err := os.OpenRoot(a.Directory)
	if err != nil {
		return "", err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return "", err
	}
	defer dir.Close()
	if err = checkOwner(dir); err != nil {
		return "", err
	}
	if st, e := root.Lstat(".lock"); e == nil && !st.Mode().IsRegular() {
		return "", fmt.Errorf("automatic capture lock is not a regular file")
	} else if e != nil && !os.IsNotExist(e) {
		return "", e
	}
	lock, err := root.OpenFile(".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	if err = lockDirectory(lock); err != nil {
		return "", err
	}
	// Closing the descriptor releases the lock, including on process death.
	files, total, err := scan(ctx, root, dir)
	if err != nil {
		return "", err
	}
	// Repair an already exceeded quota before accepting another incident. A
	// previous post-publication rotation failure must not accumulate files.
	if len(files) > a.MaxFiles || total > a.MaxStorage {
		files, total, err = rotateFn(root, dir, files, total, 0, 0, a)
		if err != nil {
			return "", fmt.Errorf("automatic storage quota remains exceeded: %w", err)
		}
	}
	var random [8]byte
	if _, err = rand.Read(random[:]); err != nil {
		return "", err
	}
	name := "blackbox-auto-" + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(random[:]) + ".bbx"
	budget := &storageWriter{ctx: ctx, dir: dir, maxFile: min(a.MaxStorage, s.Config.Control.MaxCaptureBytes)}
	err = capture.PublishInRootWithLimits(ctx, root, name, s.Config.Capture, func(w io.Writer) error {
		budget.dst = w
		return (capture.Container{Limits: s.Config.Capture}).Write(budget, c)
	})
	if err != nil {
		return "", fmt.Errorf("automatic capture %s: %w", filepath.Join(a.Directory, name), err)
	}
	path := filepath.Join(a.Directory, name)
	if _, _, err := rotateFn(root, dir, files, total, budget.written, 1, a); err != nil {
		return path, fmt.Errorf("capture published at %s but automatic rotation failed: %w", path, err)
	}
	return path, nil
}

// Rotate only after the replacement is valid and published. A failed staging
// write leaves every previously published incident in place.
func rotate(root *os.Root, dir *os.File, files []storedFile, total, added int64, incoming int, limits config.AutoCapture) ([]storedFile, int64, error) {
	removed := false
	var rotationErr error
	for len(files)+incoming > limits.MaxFiles || total+added > limits.MaxStorage {
		if len(files) == 0 {
			rotationErr = fmt.Errorf("automatic storage budget exhausted")
			break
		}
		old := files[0]
		// Do not follow a replaced path or debit bytes for a different file.
		info, err := root.Lstat(old.name)
		if err != nil {
			rotationErr = err
			break
		}
		if !info.Mode().IsRegular() || info.Size() != old.size || !info.ModTime().Equal(old.modified) {
			rotationErr = fmt.Errorf("managed capture changed during rotation: %s", old.name)
			break
		}
		if err := root.Remove(old.name); err != nil {
			rotationErr = err
			break
		}
		removed = true
		total -= old.size
		files = files[1:]
	}
	if removed {
		if err := dir.Sync(); err != nil {
			rotationErr = errors.Join(rotationErr, fmt.Errorf("sync automatic capture directory after rotation: %w", err))
		}
	}
	return files, total, rotationErr
}

func scan(ctx context.Context, root *os.Root, dir *os.File) ([]storedFile, int64, error) {
	var files []storedFile
	var total int64
	seen := 0
	for {
		entries, err := dir.ReadDir(128)
		if err != nil && err != io.EOF {
			return nil, 0, err
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nil, 0, err
			}
			seen++
			if seen > config.AutoDirectoryEntries {
				return nil, 0, fmt.Errorf("automatic directory entry limit exceeded")
			}
			name := entry.Name()
			partial := strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".partial") && automaticName.MatchString(strings.TrimSuffix(strings.TrimPrefix(name, "."), ".partial"))
			if !automaticName.MatchString(name) && !partial {
				continue
			}
			info, err := root.Lstat(name)
			if err != nil {
				return nil, 0, err
			}
			if !info.Mode().IsRegular() {
				return nil, 0, fmt.Errorf("managed capture is not a regular file: %s", name)
			}
			if partial {
				if err := root.Remove(name); err != nil {
					return nil, 0, err
				}
				continue
			}
			if info.Size() > config.MaxAutoStorage-total {
				return nil, 0, fmt.Errorf("managed captures exceed supported storage accounting")
			}
			total += info.Size()
			files = append(files, storedFile{name, info.Size(), info.ModTime()})
		}
		if err == io.EOF {
			break
		}
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].modified.Equal(files[j].modified) {
			return files[i].name < files[j].name
		}
		return files[i].modified.Before(files[j].modified)
	})
	return files, total, nil
}

type storageWriter struct {
	available        func(*os.File) (uint64, error)
	ctx              context.Context
	dir              *os.File
	dst              io.Writer
	written, maxFile int64
}

func (w *storageWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	n := int64(len(p))
	if n > w.maxFile-w.written {
		return 0, fmt.Errorf("automatic capture exceeds single-file storage budget")
	}
	available := w.available
	if available == nil {
		available = freeBytes
	}
	free, err := available(w.dir)
	if err != nil {
		return 0, err
	}
	if free < uint64(config.AutoMinFreeBytes+n) {
		return 0, fmt.Errorf("insufficient free space for automatic capture (keep at least %d bytes free)", config.AutoMinFreeBytes)
	}
	written, err := w.dst.Write(p)
	w.written += int64(written)
	return written, err
}
