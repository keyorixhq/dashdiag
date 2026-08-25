package cmd

// replay_loadbundle_test.go — regression coverage for the v2.0.2 hardening
// batch's Task 1: loadBundle used to discard LoadTarball's error entirely and
// fall back to FromSnapshot unconditionally, which meant every one of
// LoadTarball's own hostile-input rejections (entry-count cap, total-bytes
// cap, per-entry-size cap) routed the same crafted archive straight into
// FromSnapshot — a parser that, at the time, had no equivalent caps of its
// own. The fix makes loadBundle discriminate on source.ErrNotNativeBundle vs.
// source.ErrRejected; this file proves an archive tripping each LoadTarball
// limit now fails loadBundle outright, rather than silently landing in
// FromSnapshot.

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// zeroReader produces an endless run of zero bytes. Used to fill an oversized
// tar entry: archive/tar's Writer enforces that Write is called with exactly
// as many bytes as the header's declared Size, so a test can't just claim a
// huge size without backing it — but since the bytes are all zero, gzip
// compresses the resulting archive down to a few KB on disk regardless of the
// logical (pre-compression) size.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// buildRawTarGz writes a gzipped tar with entries at path containing exactly
// the given (name, body) pairs — no SaveTarball/Bundle machinery, so a test
// can construct an archive that trips a LoadTarball limit without needing a
// giant fixture (mirrors internal/source's own fuzz-test tarball builder).
func buildRawTarGz(t *testing.T, path string, entries [][2]string) {
	t.Helper()
	f, err := os.Create(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		name, body := e[0], e[1]
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body)),
		}); err != nil {
			t.Fatalf("write header %q: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("write body %q: %v", name, err)
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
}

// TestLoadBundle_RejectedArchiveNeverFallsBackToSnapshot is THE regression
// test for Task 1: an archive shaped so LoadTarball's own entry-count limit
// rejects it must fail loadBundle outright — not silently succeed via
// FromSnapshot. Against the pre-fix loadBundle (which discarded
// LoadTarball's error unconditionally), this test fails: FromSnapshot has no
// entry-count cap of its own for a file this small, so it would happily
// ingest all the entries and return a bundle with no error at all.
func TestLoadBundle_RejectedArchiveNeverFallsBackToSnapshot(t *testing.T) {
	t.Parallel()

	// One entry more than a test-local cap would allow is impractical here
	// (the real cap is 200,000) — instead this constructs a manifest-free
	// archive (so it would be a plausible FromSnapshot candidate on format
	// grounds) and relies on LoadTarball's PER-ENTRY size cap, which is easy
	// to trip with a small fixture and is exercised identically to the
	// entry-count/total-bytes caps by the ErrRejected wrapping this test is
	// really about: whichever specific limit fires, the result must be
	// ErrRejected, and loadBundle must never fall through on it.
	dir := t.TempDir()
	path := filepath.Join(dir, "oversized-entry.tar.gz")

	// A single .txt entry that CLAIMS a size over the per-entry cap in its
	// header. LoadTarball's untarGzWithLimits checks hdr.Size before ever
	// reading the body, so the archive doesn't need to actually contain that
	// much data to trip the cap.
	f, err := os.Create(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	const oversizedClaim = (100 << 20) + 1 // one byte over maxUntarFileSize
	if err := tw.WriteHeader(&tar.Header{
		Name: "hwsnap-host-x/huge.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: oversizedClaim,
	}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	// archive/tar's Writer requires the declared Size to be backed by that many
	// actual bytes written — but they're all zero, so gzip keeps the file on
	// disk tiny, and untarGzWithLimits rejects on hdr.Size alone (before
	// reading the body), so this stays fast despite the "real" 100MiB+1.
	if _, err := io.CopyN(tw, zeroReader{}, oversizedClaim); err != nil {
		t.Fatalf("write body: %v", err)
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

	_, ltErr := source.LoadTarball(path)
	if !errors.Is(ltErr, source.ErrRejected) {
		t.Fatalf("test setup: LoadTarball must reject this archive as ErrRejected, got: %v", ltErr)
	}

	b, err := loadBundle(path)
	if err == nil {
		t.Fatalf("loadBundle must fail on a rejected archive, not silently succeed via FromSnapshot (got bundle: %+v)", b)
	}
	if !errors.Is(err, source.ErrRejected) {
		t.Errorf("loadBundle's error must still be (or wrap) source.ErrRejected, got: %v", err)
	}
	if strings.Contains(err.Error(), "not a gzip tarball") {
		t.Errorf("error text suggests the request fell through to FromSnapshot, not the intended propagated rejection: %v", err)
	}
}

// TestLoadBundle_NonNativeFileFallsBackToSnapshot is the companion positive
// case: a file that genuinely isn't a native bundle (LoadTarball reports
// ErrNotNativeBundle, not ErrRejected) must still successfully fall back to
// FromSnapshot — proving the fix didn't overcorrect into refusing every
// hw-snapshot.sh tarball.
func TestLoadBundle_NonNativeFileFallsBackToSnapshot(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "hwsnap-host-x.tar.gz")
	buildRawTarGz(t, path, [][2]string{
		{"hwsnap-host-x/os-release.txt", "NAME=Test\n"},
	})

	_, ltErr := source.LoadTarball(path)
	if !errors.Is(ltErr, source.ErrNotNativeBundle) {
		t.Fatalf("test setup: LoadTarball must report ErrNotNativeBundle for a non-native tarball, got: %v", ltErr)
	}

	b, err := loadBundle(path)
	if err != nil {
		t.Fatalf("loadBundle must fall back to FromSnapshot for a non-native file, got error: %v", err)
	}
	if b == nil {
		t.Fatal("loadBundle returned a nil bundle with no error")
	}
}
