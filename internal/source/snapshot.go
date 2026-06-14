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
	f, err := os.Open(tarballPath) // #nosec G304 -- operator-supplied snapshot path
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("not a gzip tarball: %w", err)
	}
	defer gz.Close()

	b := NewBundle()
	b.Manifest.Note = "ingested from hw-snapshot.sh: " + filepath.Base(tarballPath)

	tr := tar.NewReader(gz)
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
		base := filepath.Base(hdr.Name)
		if !strings.HasSuffix(base, ".txt") {
			continue // skip .err/.exit/.missing/MANIFEST and command blobs
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
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
	for _, line := range strings.Split(content, "\n") {
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
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
