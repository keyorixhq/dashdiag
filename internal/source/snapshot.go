package source

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// directCopy maps hw-snapshot.sh's flat filenames to the real paths they hold,
// for the files it copies verbatim rather than via dumptree section headers.
var directCopy = map[string]string{
	"os-release.txt":   "/etc/os-release",
	"proc-cpuinfo.txt": "/proc/cpuinfo",
	"proc-cmdline.txt": "/proc/cmdline",
	"proc-mdstat.txt":  "/proc/mdstat",
}

var sectionHeader = regexp.MustCompile(`^===== (.+) =====$`)

// maxSnapshotIngestBytes bounds FromSnapshot's total accumulated bytes.
// Deliberately NOT maxUntarTotalBytes (tarball.go, 2 GiB): that bound was
// sized for LoadTarball's disk extraction, where each entry is written to a
// temp file and released. FromSnapshot never touches disk — every ingested
// entry's decoded content is held in memory for the life of the returned
// Bundle (b.files, see ingestSnapshotFile) — so reusing the disk-sized bound
// here would let a crafted snapshot hold up to 2 GiB in RAM, not just spike
// briefly during extraction. 256 MiB is generous for a real hw-snapshot.sh
// run (a few thousand small text files) while keeping the in-memory ceiling
// an order of magnitude below the disk bound.
const maxSnapshotIngestBytes int64 = 256 << 20

// FromSnapshot ingests the FILE layer of an hw-snapshot.sh tarball into a
// replayable Bundle. dumptree sections (`===== /path =====`) and the handful of
// direct-copied files are keyed by their real absolute path — the same key the
// native Source uses — so file-based collectors (thermal, edac, cpufreq, cpuinfo,
// amdgpu sysfs) replay straight from a returned tarball.
//
// Command outputs in the snapshot are NOT ingested: the script's friendly labels
// do not encode argv. Command replay arrives with native `dsd capture --raw`
// (Phase 2); until then a command-based collector hits ErrNotRecorded on replay,
// which is the correct loud signal rather than a silent wrong answer.
func FromSnapshot(tarballPath string) (*Bundle, error) {
	return fromSnapshotWithLimits(tarballPath, maxUntarEntries, maxSnapshotIngestBytes)
}

// fromSnapshotWithLimits is FromSnapshot's testable core — maxEntries/
// maxTotalBytes are parameterized so a test can exercise the breadth caps with
// a handful of tiny entries instead of constructing a snapshot large enough to
// hit the real (200k entry / 2GiB) production limits. Mirrors
// untarGzWithLimits in tarball.go: FromSnapshot previously bounded only a
// single entry's size (maxUntarFileSize below), not the archive's total entry
// count or cumulative bytes, unlike untarGzWithLimits — a crafted
// hw-snapshot.sh-style tarball with many small .txt entries, each under the
// per-file cap, could still exhaust memory/CPU on `dsd replay`, which falls
// back to this function whenever LoadTarball rejects the file as not a native
// raw-v1 bundle (cmd/replay.go's loadBundle).
func fromSnapshotWithLimits(tarballPath string, maxEntries int, maxTotalBytes int64) (*Bundle, error) {
	f, err := os.Open(tarballPath) // #nosec G304 -- operator-supplied snapshot path
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("not a gzip tarball: %w", err)
	}
	defer func() { _ = gz.Close() }()

	b := NewBundle()
	b.Manifest.Note = "ingested from hw-snapshot.sh: " + filepath.Base(tarballPath)

	tr := tar.NewReader(gz)
	var entries int
	var totalBytes int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		entries++
		if entries > maxEntries {
			return nil, fmt.Errorf("snapshot has more than %d entries — refusing to ingest further", maxEntries)
		}
		base := filepath.Base(hdr.Name)
		if !strings.HasSuffix(base, ".txt") {
			continue // skip .err/.exit/.missing/MANIFEST and command blobs
		}
		if hdr.Size < 0 || hdr.Size > maxUntarFileSize {
			return nil, fmt.Errorf("snapshot entry %q exceeds maximum size (%d bytes)", hdr.Name, maxUntarFileSize)
		}
		if totalBytes+hdr.Size > maxTotalBytes {
			return nil, fmt.Errorf("snapshot's total ingested size exceeds %d bytes — refusing to ingest further", maxTotalBytes)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxUntarFileSize+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > maxUntarFileSize {
			return nil, fmt.Errorf("snapshot entry %q exceeds maximum size (%d bytes)", hdr.Name, maxUntarFileSize)
		}
		totalBytes += int64(len(data))
		ingestSnapshotFile(b, base, string(data))
	}
	return b, nil
}

func ingestSnapshotFile(b *Bundle, base, content string) {
	if real, ok := directCopy[base]; ok {
		b.putFile(real, []byte(content), nil)
		return
	}
	if !sectionHeader.MatchString(firstLine(content)) && !strings.Contains(content, "\n=====") {
		return // not a dumptree dump; nothing path-keyed to extract
	}
	var curPath string
	var buf []string
	flush := func() {
		if curPath == "" {
			return
		}
		body := strings.Join(buf, "\n")
		body = strings.TrimSuffix(body, "\n") // drop the trailing echo blank line
		b.putFile(curPath, []byte(body), nil)
	}
	for line := range strings.SplitSeq(content, "\n") {
		if m := sectionHeader.FindStringSubmatch(line); m != nil {
			flush()
			curPath = strings.TrimSpace(m[1])
			buf = buf[:0]
			continue
		}
		buf = append(buf, line)
	}
	flush()
}

func firstLine(s string) string {
	if before, _, ok := strings.Cut(s, "\n"); ok {
		return before
	}
	return s
}
