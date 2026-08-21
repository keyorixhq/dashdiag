package source

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFromSnapshotOpenFailure exercises the os.Open failure path — a tarball
// path that does not exist.
func TestFromSnapshotOpenFailure(t *testing.T) {
	t.Parallel()

	_, err := FromSnapshot(filepath.Join(t.TempDir(), "does-not-exist.tar.gz"))
	if err == nil {
		t.Fatal("FromSnapshot of a missing path should fail")
	}
}

// TestFromSnapshotNotGzip exercises the gzip.NewReader failure path — a file
// that exists but is not gzip-compressed.
func TestFromSnapshotNotGzip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "plain.tar.gz")
	if err := os.WriteFile(path, []byte("not actually gzip data"), 0o644); err != nil {
		t.Fatalf("write plain file: %v", err)
	}
	_, err := FromSnapshot(path)
	if err == nil {
		t.Fatal("FromSnapshot of a non-gzip file should fail")
	}
}

// TestFromSnapshotBadTarEntry exercises the tr.Next() failure path — valid
// gzip but truncated/corrupt tar content inside it.
func TestFromSnapshotBadTarEntry(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "corrupt.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	// Write a gzip stream that decompresses to garbage (not a valid tar header).
	if _, err := gz.Write([]byte("this is not a valid tar header at all, far too short")); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}

	_, err = FromSnapshot(path)
	if err == nil {
		t.Fatal("FromSnapshot of a gzip stream with invalid tar content should fail")
	}
}

// TestFromSnapshotTruncatedEntry exercises the io.ReadAll failure path — a
// .txt tar entry whose header declares a size larger than the bytes actually
// present in the archive (a truncated capture), which the tar reader reports
// as unexpected EOF partway through reading the entry.
func TestFromSnapshotTruncatedEntry(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "truncated.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "hwsnap-host-x/big.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 100,
	}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := tw.Write([]byte("short")); err != nil {
		t.Fatalf("write short body: %v", err)
	}
	// Deliberately do NOT call tw.Close() — leave the archive truncated so the
	// declared 100-byte entry only has 5 bytes actually available.
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}

	if _, err := FromSnapshot(path); err == nil {
		t.Fatal("FromSnapshot of a truncated tar entry should fail")
	}
}

// TestFromSnapshotRejectsOversizedEntry covers internal-source-02-02:
// FromSnapshot must reject a tar entry whose declared size exceeds
// maxUntarFileSize rather than reading it fully into memory with an unbounded
// io.ReadAll — the same cap untarGz already enforces in tarball.go. Writes a
// real oversized (highly compressible, all-zero) entry so the tar stream is
// well-formed; the point is that FromSnapshot must refuse to materialize it,
// not that the bytes are hard to produce.
func TestFromSnapshotRejectsOversizedEntry(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "huge.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	const oversize = maxUntarFileSize + 1024
	if err := tw.WriteHeader(&tar.Header{
		Name: "hwsnap-host-x/huge.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: oversize,
	}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	buf := make([]byte, 1<<20) // 1MiB zero chunk, reused
	for written := int64(0); written < oversize; {
		n := int64(len(buf))
		if remaining := oversize - written; remaining < n {
			n = remaining
		}
		if _, err := tw.Write(buf[:n]); err != nil {
			t.Fatalf("write body: %v", err)
		}
		written += n
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}

	if _, err := FromSnapshot(path); err == nil {
		t.Fatal("FromSnapshot of an oversized tar entry should fail, not read it fully into memory")
	}
}

// TestFromSnapshotSkipsNonRegularAndNonTxt verifies FromSnapshot skips
// non-regular tar entries (e.g. directories) and non-.txt files (.err/.exit/
// MANIFEST/command blobs), ingesting only the recognised .txt payloads.
func TestFromSnapshotSkipsNonRegularAndNonTxt(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "snap.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	// A directory entry — must be skipped (Typeflag != TypeReg).
	if err := tw.WriteHeader(&tar.Header{Name: "hwsnap-host-x/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatalf("write dir header: %v", err)
	}
	// A non-.txt file — must be skipped.
	skipBody := "should not be ingested"
	if err := tw.WriteHeader(&tar.Header{
		Name: "hwsnap-host-x/some-command.exit", Typeflag: tar.TypeReg,
		Mode: 0o644, Size: int64(len(skipBody)),
	}); err != nil {
		t.Fatalf("write .exit header: %v", err)
	}
	if _, err := tw.Write([]byte(skipBody)); err != nil {
		t.Fatalf("write .exit body: %v", err)
	}
	// A recognised direct-copy .txt file — must be ingested.
	osRelease := "ID=debian\n"
	if err := tw.WriteHeader(&tar.Header{
		Name: "hwsnap-host-x/os-release.txt", Typeflag: tar.TypeReg,
		Mode: 0o644, Size: int64(len(osRelease)),
	}); err != nil {
		t.Fatalf("write os-release header: %v", err)
	}
	if _, err := tw.Write([]byte(osRelease)); err != nil {
		t.Fatalf("write os-release body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}

	b, err := FromSnapshot(path)
	if err != nil {
		t.Fatalf("FromSnapshot: %v", err)
	}
	if got, ok := b.getFile("/etc/os-release"); !ok || string(got.data) != osRelease {
		t.Fatalf("expected /etc/os-release to be ingested, got %+v ok=%v", got, ok)
	}
	// The skipped .exit content must not have been ingested under any path —
	// spot-check that no file recorded its body.
	for path, rec := range b.files {
		if string(rec.data) == skipBody {
			t.Fatalf("non-.txt entry %q was ingested, should have been skipped", path)
		}
	}
}

// TestFromSnapshotWithLimits_EntryCountCapped is the regression test for the
// gap the adversarial untrusted-input review found: FromSnapshot bounded a
// single entry's size but not the archive's total entry count, unlike
// untarGzWithLimits in tarball.go. Mirrors
// TestUntarGzWithLimits_EntryCountCapped's shape.
func TestFromSnapshotWithLimits_EntryCountCapped(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "many-entries.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for i := range 5 {
		name := "hwsnap-host-x/f" + string(rune('a'+i)) + ".txt"
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write([]byte("x")); err != nil {
			t.Fatalf("write body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}

	if _, err := fromSnapshotWithLimits(path, 3, maxUntarTotalBytes); err == nil {
		t.Fatal("expected an error when the snapshot exceeds the entry-count cap")
	}
	if _, err := fromSnapshotWithLimits(path, 10, maxUntarTotalBytes); err != nil {
		t.Errorf("unexpected error under the entry-count cap: %v", err)
	}
}

// TestFromSnapshotWithLimits_TotalBytesCapped is the regression test for the
// total-size half of the same gap: several .txt entries, each within the
// per-file cap, whose combined size exceeds the archive-wide total must be
// refused rather than ingested in full. Mirrors
// TestUntarGzWithLimits_TotalBytesCapped's shape.
func TestFromSnapshotWithLimits_TotalBytesCapped(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "big-total.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, name := range []string{"hwsnap-host-x/a.txt", "hwsnap-host-x/b.txt", "hwsnap-host-x/c.txt"} {
		body := strings.Repeat("x", 100)
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("write body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}

	if _, err := fromSnapshotWithLimits(path, maxUntarEntries, 250); err == nil {
		t.Fatal("expected an error when the snapshot exceeds the total-bytes cap")
	}
	if _, err := fromSnapshotWithLimits(path, maxUntarEntries, 1000); err != nil {
		t.Errorf("unexpected error under the total-bytes cap: %v", err)
	}
}

// TestIngestSnapshotFileNonDumptreeIgnored verifies ingestSnapshotFile skips
// content that is neither a recognised direct-copy filename nor a dumptree
// section dump (no "===== " header anywhere) — nothing path-keyed to extract.
func TestIngestSnapshotFileNonDumptreeIgnored(t *testing.T) {
	t.Parallel()

	b := NewBundle()
	ingestSnapshotFile(b, "random-notes.txt", "just some free-form text\nwith multiple lines\n")
	if len(b.files) != 0 {
		t.Fatalf("expected no files ingested from non-dumptree content, got %d: %+v", len(b.files), b.files)
	}
}
