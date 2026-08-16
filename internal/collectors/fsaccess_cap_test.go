//go:build linux

package collectors

import (
	"errors"
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

// TestReadFile_TooLargeSkipsFullRead guards internal-collectors-18-02/19-03:
// when Stat reports a size far beyond any legitimate file (maxSafeReadBytes),
// readFile must return errFileTooLarge WITHOUT materializing the recorded
// payload at all — the whole point is never fully reading a pathologically
// huge file (attacker-flooded log, or a malicious replay bundle entry) into
// memory just to truncate it afterwards. We seed a PutFile payload that would
// prove the read happened if returned, and a PutStat claiming a size over the
// threshold; the result must be the sentinel error and nil data, not the
// payload capped to maxCappedFileBytes.
func TestReadFile_TooLargeSkipsFullRead(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/var/log/audit/audit.log", source.FileMeta{Size: maxSafeReadBytes + 1})
		b.PutFile("/var/log/audit/audit.log", []byte("this payload must never be returned"))
	})
	data, err := readFile("/var/log/audit/audit.log")
	if !errors.Is(err, errFileTooLarge) {
		t.Fatalf("readFile error = %v, want errFileTooLarge", err)
	}
	if data != nil {
		t.Errorf("readFile data = %q, want nil on the too-large path", data)
	}
}

// TestOpenFile_TooLargeSkipsFullRead is the openFile side of the same guard.
func TestOpenFile_TooLargeSkipsFullRead(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/var/log/secure", source.FileMeta{Size: maxSafeReadBytes + 1})
		b.PutFile("/var/log/secure", []byte("this payload must never be returned"))
	})
	rc, err := openFile("/var/log/secure")
	if !errors.Is(err, errFileTooLarge) {
		t.Fatalf("openFile error = %v, want errFileTooLarge", err)
	}
	if rc != nil {
		t.Error("openFile reader = non-nil, want nil on the too-large path")
	}
}

// TestReadFile_UnderSafeThresholdStillReads guards the boundary just under
// maxSafeReadBytes: a file this large is still legitimate (e.g. a genuinely
// big but not pathological log) and must be read and tail-capped as before,
// not rejected.
func TestReadFile_UnderSafeThresholdStillReads(t *testing.T) {
	oversized := strings.Repeat("c", maxCappedFileBytes) + "TAIL-MARKER"
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/var/log/big.log", source.FileMeta{Size: maxSafeReadBytes - 1})
		b.PutFile("/var/log/big.log", []byte(oversized))
	})
	data, err := readFile("/var/log/big.log")
	if err != nil {
		t.Fatalf("readFile error: %v", err)
	}
	if len(data) != maxCappedFileBytes {
		t.Fatalf("len(data) = %d, want exactly the cap %d", len(data), maxCappedFileBytes)
	}
	if !strings.HasSuffix(string(data), "TAIL-MARKER") {
		t.Error("readFile must still keep the TAIL under the too-large threshold")
	}
}

// TestReadFile_NoRecordedStatFallsBackToFullReadCap guards backward
// compatibility with a replay bundle captured BEFORE this size probe
// existed: Stat and ReadFile are independently keyed in a Bundle (see
// internal/source/bundle.go), so an older bundle that only recorded
// ReadFile for a path has no Stat entry at all. statSizeHint must treat that
// as "unknown" (-1), not "too large" or "empty", and readFile must fall
// through to the pre-existing full-read-then-cap behaviour rather than
// erroring out on a bundle that used to replay fine.
func TestReadFile_NoRecordedStatFallsBackToFullReadCap(t *testing.T) {
	oversized := strings.Repeat("d", maxCappedFileBytes) + "TAIL-MARKER"
	withFixtureSource(t, func(b *source.Bundle) {
		// Deliberately no PutStat call — simulates an old bundle.
		b.PutFile("/var/log/oldbundle.log", []byte(oversized))
	})
	data, err := readFile("/var/log/oldbundle.log")
	if err != nil {
		t.Fatalf("readFile error: %v", err)
	}
	if len(data) != maxCappedFileBytes {
		t.Fatalf("len(data) = %d, want exactly the cap %d", len(data), maxCappedFileBytes)
	}
	if !strings.HasSuffix(string(data), "TAIL-MARKER") {
		t.Error("readFile must keep the TAIL when falling back on an unrecorded Stat")
	}
}

// statPanicsSource is a minimal source.Source whose embedded interface is
// left nil for every method except ReadFile, mirroring the "other methods
// left nil — an unexpected call panics and flags itself" pattern used
// throughout this package's tests (see e.g. permissionSource in
// security_linux_test.go). Calling Stat() on it panics with a nil-pointer
// dereference, exactly like the dozens of pre-existing partial test doubles
// across the package that predate the Stat probe this test guards.
type statPanicsSource struct {
	source.Source
}

func (s statPanicsSource) ReadFile(path string) ([]byte, error) {
	return []byte("live data, no stat needed"), nil
}

// TestStatSizeHint_RecoversFromPanickingSource guards readFile/openFile
// against every one of the package's pre-existing partial-Source test
// doubles that don't implement Stat: since these helpers are the shared
// low-level read path used throughout internal/collectors, a mandatory
// Stat() call must not turn a test double that never implemented Stat into a
// panic. statSizeHint recovers and reports "unknown" (-1), and readFile must
// still complete successfully via ReadFile.
func TestStatSizeHint_RecoversFromPanickingSource(t *testing.T) {
	prev := SetSource(statPanicsSource{})
	defer SetSource(prev)

	if got := statSizeHint("/anything"); got != -1 {
		t.Fatalf("statSizeHint = %d, want -1 (recovered from the panicking Stat)", got)
	}
	data, err := readFile("/anything")
	if err != nil {
		t.Fatalf("readFile error: %v", err)
	}
	if string(data) != "live data, no stat needed" {
		t.Errorf("readFile data = %q, want the ReadFile-only source's payload", data)
	}
}
