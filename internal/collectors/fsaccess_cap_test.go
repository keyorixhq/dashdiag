//go:build linux

package collectors

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestReadFile_CapsOversizedFile guards internal-collectors-12-05: readFile
// must not hand an unbounded amount of data to a caller. A file (or, under
// `dsd replay`, a malicious capture bundle entry) larger than
// maxCappedFileBytes must come back truncated to that cap, not in full — and
// truncation must keep the TAIL (the most recent bytes), since every current
// caller that reads an append-only log-style file cares about recency, not
// the earliest bytes written.
func TestReadFile_CapsOversizedFile(t *testing.T) {
	oversized := strings.Repeat("a", maxCappedFileBytes) + "TAIL-MARKER"
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/log/huge.log", []byte(oversized))
	})
	data, err := readFile("/var/log/huge.log")
	if err != nil {
		t.Fatalf("readFile error: %v", err)
	}
	if len(data) != maxCappedFileBytes {
		t.Fatalf("len(data) = %d, want exactly the cap %d", len(data), maxCappedFileBytes)
	}
	if !strings.HasSuffix(string(data), "TAIL-MARKER") {
		t.Error("readFile must keep the TAIL of an oversized file, not the head")
	}
}

// TestReadFile_UnderCapUnchanged guards against an over-eager cap: a file
// under the limit must come back byte-for-byte unchanged.
func TestReadFile_UnderCapUnchanged(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/hostname", []byte("host1\n"))
	})
	data, err := readFile("/etc/hostname")
	if err != nil {
		t.Fatalf("readFile error: %v", err)
	}
	if string(data) != "host1\n" {
		t.Errorf("readFile = %q, want %q", data, "host1\n")
	}
}

// TestOpenFile_CapsOversizedFile guards the same cap on openFile, the
// io.ReadCloser-returning drop-in for os.Open.
func TestOpenFile_CapsOversizedFile(t *testing.T) {
	oversized := strings.Repeat("b", maxCappedFileBytes+1024)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/log/huge2.log", []byte(oversized))
	})
	rc, err := openFile("/var/log/huge2.log")
	if err != nil {
		t.Fatalf("openFile error: %v", err)
	}
	defer rc.Close() //nolint:errcheck
	buf := make([]byte, 0, maxCappedFileBytes+2048)
	tmp := make([]byte, 4096)
	for {
		n, rerr := rc.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if rerr != nil {
			break
		}
	}
	if len(buf) != maxCappedFileBytes {
		t.Fatalf("openFile content len = %d, want exactly the cap %d", len(buf), maxCappedFileBytes)
	}
}

// TestGlob_CapsEntryCount guards internal-collectors-12-05's glob side: a
// pattern matching more than maxCappedDirEntries paths (e.g. from a malicious
// replay bundle) must come back capped, not with every match allocated.
func TestGlob_CapsEntryCount(t *testing.T) {
	matches := make([]string, maxCappedDirEntries+10)
	for i := range matches {
		matches[i] = "/sys/class/fake/entry"
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/fake/*", matches)
	})
	got, err := glob("/sys/class/fake/*")
	if err != nil {
		t.Fatalf("glob error: %v", err)
	}
	if len(got) != maxCappedDirEntries {
		t.Fatalf("len(got) = %d, want exactly the cap %d", len(got), maxCappedDirEntries)
	}
}

// TestReadDirNames_CapsEntryCount guards the readDirNames side of the same
// finding: a directory (or replay bundle entry) claiming more than
// maxCappedDirEntries names must come back capped.
func TestReadDirNames_CapsEntryCount(t *testing.T) {
	names := make([]string, maxCappedDirEntries+10)
	for i := range names {
		names[i] = "entry"
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc/fakehuge", names)
	})
	got, err := readDirNames("/proc/fakehuge")
	if err != nil {
		t.Fatalf("readDirNames error: %v", err)
	}
	if len(got) != maxCappedDirEntries {
		t.Fatalf("len(got) = %d, want exactly the cap %d", len(got), maxCappedDirEntries)
	}
}
