package source

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
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
