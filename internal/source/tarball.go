package source

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const maxUntarFileSize int64 = 100 << 20 // 100 MiB per extracted file

// internal-source-02-03: maxUntarFileSize alone bounds each entry but not the
// bundle as a whole — a crafted archive with many entries just under the
// per-file cap could still exhaust disk space on extraction. maxUntarEntries
// and maxUntarTotalBytes bound the count and running total across the whole
// archive; a real dsd capture bundle is a few thousand small files at most.
const (
	maxUntarEntries    = 200_000
	maxUntarTotalBytes = 2 << 30 // 2 GiB
)

// SaveTarball writes the bundle as a gzipped tar in the raw-v1 layout. This is
// the artifact `dsd capture --raw` hands back: one self-contained file.
func (b *Bundle) SaveTarball(path string) error {
	tmp, err := os.MkdirTemp("", "dsd-raw-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := b.Save(tmp); err != nil {
		return err
	}
	return tarGzDir(tmp, path)
}

// LoadTarball reads a bundle previously written by SaveTarball.
func LoadTarball(path string) (*Bundle, error) {
	tmp, err := os.MkdirTemp("", "dsd-raw-*")
	if err != nil {
		return nil, err
	}
	if err := untarGz(path, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	// Load reads every blob into []byte before returning — tmp is fully consumed
	// after this call and can be removed regardless of the outcome.
	b, err := Load(tmp)
	_ = os.RemoveAll(tmp)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func tarGzDir(srcDir, dstPath string) error {
	// 0600: a capture bundle can carry sanitized-but-still-sensitive host data
	// (paths, hostnames, config); don't leave it world/group-readable on a
	// shared multi-user box merely because os.Create defers to umask.
	// O_NOFOLLOW: dstPath is operator/caller-chosen (--out, or an MCP tool's
	// out_path) and can be a fixed/predictable path. Without this, a
	// pre-existing symlink at dstPath would be followed and its target
	// silently overwritten with the bundle instead of the write being
	// refused — the same hazard cmd/root.go's createOutFile guards for --out.
	f, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- operator-chosen output path; O_NOFOLLOW blocks symlink-follow
	if errors.Is(err, syscall.ELOOP) {
		return fmt.Errorf("source: refusing to write through a symlink at %q", dstPath)
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	walkErr := filepath.Walk(srcDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(srcDir, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p) // #nosec G304 G122 -- srcDir is our own freshly-created temp dir; no untrusted symlinks
		if err != nil {
			return err
		}
		hdr := &tar.Header{Name: rel, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
	// Close the writers explicitly so a flush error surfaces instead of being
	// swallowed by a deferred close (a dropped flush on a writer loses data).
	if walkErr != nil {
		_ = tw.Close()
		_ = gz.Close()
		return walkErr
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return err
	}
	return gz.Close()
}

func untarGz(srcPath, dstDir string) error {
	return untarGzWithLimits(srcPath, dstDir, maxUntarEntries, maxUntarTotalBytes)
}

// untarGzWithLimits is untarGz's testable core — maxEntries/maxTotalBytes are
// parameterized so a test can exercise the breadth caps with a handful of
// tiny entries instead of constructing an archive large enough to hit the
// real (200k entry / 2GiB) production limits.
func untarGzWithLimits(srcPath, dstDir string, maxEntries int, maxTotalBytes int64) error {
	f, err := os.Open(srcPath) // #nosec G304 -- operator-supplied bundle path
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	var entries int
	var totalBytes int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		entries++
		if entries > maxEntries {
			return fmt.Errorf("archive has more than %d entries — refusing to extract further", maxEntries)
		}
		// Guard against path traversal in a crafted archive.
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			continue
		}
		dst := filepath.Join(dstDir, clean)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if hdr.Size < 0 || hdr.Size > maxUntarFileSize {
			return fmt.Errorf("tar entry %q exceeds maximum size (%d bytes)", hdr.Name, maxUntarFileSize)
		}
		if totalBytes+hdr.Size > maxTotalBytes {
			return fmt.Errorf("archive's total extracted size exceeds %d bytes — refusing to extract further", maxTotalBytes)
		}
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- dst is under our temp dir
		if err != nil {
			return err
		}
		n, err := io.Copy(out, io.LimitReader(tr, maxUntarFileSize+1))
		if err != nil {
			_ = out.Close()
			return err
		}
		if n > maxUntarFileSize {
			_ = out.Close()
			return fmt.Errorf("tar entry %q exceeds maximum size (%d bytes)", hdr.Name, maxUntarFileSize)
		}
		totalBytes += n
		if err := out.Close(); err != nil {
			return err
		}
	}
	return nil
}
