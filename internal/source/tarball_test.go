package source

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSaveTarballMkdirTempFailure exercises SaveTarball's os.MkdirTemp
// failure path by pointing TMPDIR at a directory that does not exist —
// MkdirTemp's own stat of the base dir fails before anything is written.
func TestSaveTarballMkdirTempFailure(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "no-such-base-dir"))

	b := NewBundle()
	dst := filepath.Join(t.TempDir(), "out.tar.gz")
	if err := b.SaveTarball(dst); err == nil {
		t.Fatal("SaveTarball should fail when os.MkdirTemp's base directory does not exist")
	}
}

// TestLoadTarballMkdirTempFailure exercises LoadTarball's os.MkdirTemp
// failure path, mirroring TestSaveTarballMkdirTempFailure.
func TestLoadTarballMkdirTempFailure(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "no-such-base-dir"))

	if _, err := LoadTarball(filepath.Join(t.TempDir(), "whatever.tar.gz")); err == nil {
		t.Fatal("LoadTarball should fail when os.MkdirTemp's base directory does not exist")
	}
}

// TestSaveTarballWalkFailure exercises SaveTarball's propagation of a Save
// failure (Save is exercised directly in persist_test.go; here we just
// confirm SaveTarball forwards the error rather than swallowing it, using an
// unwritable destination path).
func TestSaveTarballBadDestination(t *testing.T) {
	t.Parallel()

	b := NewBundle()
	b.PutFile("/etc/present", []byte("data"))
	// A destination inside a nonexistent parent directory (tarGzDir's
	// os.OpenFile has no MkdirAll) must fail.
	dst := filepath.Join(t.TempDir(), "no-such-parent", "out.tar.gz")
	if err := b.SaveTarball(dst); err == nil {
		t.Fatal("SaveTarball into a nonexistent parent dir should fail")
	}
}

// TestSaveTarballRefusesSymlink guards cmd-09-02: SaveTarball's dstPath is
// operator/caller-chosen (--out on `dsd capture --raw`, or an MCP tool's
// out_path) and can be a fixed/predictable path. tarGzDir's os.OpenFile
// previously used O_CREATE|O_TRUNC with no O_EXCL/O_NOFOLLOW, so a
// pre-existing symlink at dstPath would be followed and its target silently
// overwritten with the bundle. SaveTarball must refuse instead.
func TestSaveTarballRefusesSymlink(t *testing.T) {
	t.Parallel()

	victim := filepath.Join(t.TempDir(), "victim.tar.gz")
	if err := os.WriteFile(victim, []byte("original contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "out.tar.gz")
	if err := os.Symlink(victim, dst); err != nil {
		t.Fatal(err)
	}

	b := NewBundle()
	b.PutFile("/etc/present", []byte("data"))
	if err := b.SaveTarball(dst); err == nil {
		t.Fatal("SaveTarball should refuse to write through a pre-existing symlink")
	}

	data, err := os.ReadFile(victim) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original contents" {
		t.Errorf("victim file was overwritten: %q", data)
	}
}

// TestLoadTarballOpenFailure exercises LoadTarball's untarGz open-failure path.
func TestLoadTarballOpenFailure(t *testing.T) {
	t.Parallel()

	_, err := LoadTarball(filepath.Join(t.TempDir(), "missing.tar.gz"))
	if err == nil {
		t.Fatal("LoadTarball of a missing path should fail")
	}
}

// TestLoadTarballNotGzip exercises untarGz's gzip.NewReader failure path.
func TestLoadTarballNotGzip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "plain.tar.gz")
	if err := os.WriteFile(path, []byte("definitely not gzip"), 0o644); err != nil {
		t.Fatalf("write plain file: %v", err)
	}
	if _, err := LoadTarball(path); err == nil {
		t.Fatal("LoadTarball of a non-gzip file should fail")
	}
}

// TestLoadTarballBadTarEntry exercises untarGz's tr.Next() failure path — a
// valid gzip stream whose payload is not a valid tar stream.
func TestLoadTarballBadTarEntry(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "corrupt.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	if _, err := gz.Write([]byte("garbage that is not a tar header")); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}

	if _, err := LoadTarball(path); err == nil {
		t.Fatal("LoadTarball of a gzip stream with invalid tar content should fail")
	}
}

// TestLoadTarballPathTraversalGuard verifies untarGz skips a crafted tar
// entry that attempts path traversal (a "../" name or an absolute path)
// rather than writing outside the destination directory.
func TestLoadTarballPathTraversalGuard(t *testing.T) {
	t.Parallel()

	src := filepath.Join(t.TempDir(), "evil.tar.gz")
	f, err := os.Create(src)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	evilBody := "should never land on disk outside dstDir"
	entries := []string{"../escaped.txt", "/etc/escaped-absolute.txt"}
	for _, name := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(evilBody)),
		}); err != nil {
			t.Fatalf("write header %q: %v", name, err)
		}
		if _, err := tw.Write([]byte(evilBody)); err != nil {
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

	dst := t.TempDir()
	if err := untarGz(src, dst); err != nil {
		t.Fatalf("untarGz: %v", err)
	}

	// Neither traversal target should exist anywhere near dst's parent.
	if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "escaped.txt")); err == nil {
		t.Fatal("path-traversal entry with '..' escaped the destination directory")
	}
	if _, err := os.Stat("/etc/escaped-absolute.txt"); err == nil {
		t.Fatal("absolute-path entry escaped the destination directory (unexpectedly present in /etc)")
	}
	entriesInDst, err := os.ReadDir(dst)
	if err != nil {
		t.Fatalf("readdir dst: %v", err)
	}
	if len(entriesInDst) != 0 {
		t.Fatalf("expected no files written into dst (both entries should be skipped), got %v", entriesInDst)
	}
}

// TestTarGzDirReadFileFailure exercises tarGzDir's os.ReadFile failure path
// (and the walkErr propagation branch that closes tw/gz before returning): a
// source file that is present but unreadable (permission denied).
func TestTarGzDirReadFileFailure(t *testing.T) {
	t.Parallel()

	src := t.TempDir()
	unreadable := filepath.Join(src, "no-read.txt")
	if err := os.WriteFile(unreadable, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	chmodRestoring(t, unreadable, 0o000)

	dst := filepath.Join(t.TempDir(), "out.tar.gz")
	if err := tarGzDir(src, dst); err == nil {
		t.Fatal("tarGzDir should fail when a source file is unreadable")
	}
}

// TestTarGzDirWalkDirFailure covers the filepath.Walk callback's own err
// parameter (tarGzDir's walk func returns it unconditionally at the top) —
// distinct from TestTarGzDirReadFileFailure above, which fails later at
// os.ReadFile on a specific unreadable FILE. This one fails earlier, when
// Walk itself can't list a subdirectory's entries (no read/execute
// permission on the directory), so the callback is invoked a second time
// for that directory carrying a non-nil err.
func TestTarGzDirWalkDirFailure(t *testing.T) {
	t.Parallel()

	src := t.TempDir()
	unreadableDir := filepath.Join(src, "no-list")
	if err := os.Mkdir(unreadableDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(unreadableDir, "f.txt"), []byte("data"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	chmodRestoring(t, unreadableDir, 0o000)

	dst := filepath.Join(t.TempDir(), "out.tar.gz")
	if err := tarGzDir(src, dst); err == nil {
		t.Fatal("tarGzDir should fail when a source subdirectory can't be listed")
	}
}

// TestTarGzDirWriteHeaderFailure covers the walk callback's tw.WriteHeader
// error branch (tarball.go:112-114) using /dev/full (Linux-only — a device
// that always returns ENOSPC on write) as the destination. tw.WriteHeader
// writes through tar.Writer -> gzip.Writer -> the destination file, and in
// practice a small header write reaches the underlying device promptly
// rather than sitting in gzip's internal buffer until Close() — verified
// empirically against golang:1.26 in the Linux container before writing this
// test, since the alternative hypothesis (failure deferred to tw.Close())
// turned out not to hold for real header/data sizes.
func TestTarGzDirWriteHeaderFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/dev/full is Linux-only")
	}
	t.Parallel()

	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "f.txt"), []byte("data"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := tarGzDir(src, "/dev/full"); err == nil {
		t.Fatal("tarGzDir should fail when the destination device always returns ENOSPC")
	}
}

// TestTarGzDirRefusesSymlinkedDest covers the O_NOFOLLOW/ELOOP branch: a
// pre-existing symlink at dstPath (an operator/caller-chosen, potentially
// predictable path — --out, or an MCP tool's out_path) must be refused
// rather than followed and its target silently overwritten.
func TestTarGzDirRefusesSymlinkedDest(t *testing.T) {
	t.Parallel()

	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "f.txt"), []byte("data"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "out.tar.gz")
	if err := os.Symlink(target, dst); err != nil {
		t.Fatal(err)
	}

	err := tarGzDir(src, dst)
	if err == nil || !strings.Contains(err.Error(), "refusing to write through a symlink") {
		t.Errorf("tarGzDir() = %v, want a symlink-refusal error", err)
	}
}

// TestUntarGzSkipsNonRegularEntries verifies untarGz skips tar entries that
// are not regular files (e.g. a directory header written explicitly).
// TestUntarGzWithLimits_EntryCountCapped is the regression test for
// internal-source-02-03: maxUntarFileSize alone bounds each entry but not
// how many entries an archive may contain. A crafted archive with many
// small entries must still be refused once the entry-count cap is reached.
func TestUntarGzWithLimits_EntryCountCapped(t *testing.T) {
	t.Parallel()
	files := make(map[string]string, 5)
	for i := range 5 {
		files[fmt.Sprintf("f%d.txt", i)] = "x"
	}
	src := writeTestTarball(t, files)

	if err := untarGzWithLimits(src, t.TempDir(), 3, maxUntarTotalBytes); err == nil {
		t.Fatal("expected an error when the archive exceeds the entry-count cap")
	}
	// Below the cap: same archive succeeds.
	if err := untarGzWithLimits(src, t.TempDir(), 10, maxUntarTotalBytes); err != nil {
		t.Errorf("unexpected error under the entry-count cap: %v", err)
	}
}

// TestUntarGzWithLimits_TotalBytesCapped is the regression test for
// internal-source-02-03's total-size half: several entries, each within the
// per-file cap, whose combined size exceeds the archive-wide total must be
// refused rather than extracted in full.
func TestUntarGzWithLimits_TotalBytesCapped(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"a.txt": strings.Repeat("a", 100),
		"b.txt": strings.Repeat("b", 100),
		"c.txt": strings.Repeat("c", 100),
	}
	src := writeTestTarball(t, files)

	if err := untarGzWithLimits(src, t.TempDir(), maxUntarEntries, 250); err == nil {
		t.Fatal("expected an error when the archive exceeds the total-bytes cap")
	}
	// Below the cap: same archive succeeds.
	if err := untarGzWithLimits(src, t.TempDir(), maxUntarEntries, 1000); err != nil {
		t.Errorf("unexpected error under the total-bytes cap: %v", err)
	}
}

func TestUntarGzSkipsNonRegularEntries(t *testing.T) {
	t.Parallel()

	src := filepath.Join(t.TempDir(), "withdir.tar.gz")
	f, err := os.Create(src)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "adir/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatalf("write dir header: %v", err)
	}
	body := "real file content"
	if err := tw.WriteHeader(&tar.Header{Name: "afile.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatalf("write file header: %v", err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatalf("write file body: %v", err)
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

	dst := t.TempDir()
	if err := untarGz(src, dst); err != nil {
		t.Fatalf("untarGz: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "afile.txt"))
	if err != nil || string(got) != body {
		t.Fatalf("afile.txt = %q, %v", got, err)
	}
	// The explicit directory entry must not have been treated as a regular
	// file (no attempt to write content to a path named "adir/").
	if fi, err := os.Stat(filepath.Join(dst, "adir")); err == nil && !fi.IsDir() {
		t.Fatalf("adir should either not exist as a file or be a real dir, got mode %v", fi.Mode())
	}
}

// TestUntarGzTruncatedEntry exercises untarGz's io.Copy failure path: a
// regular-file tar entry whose header declares a size larger than the bytes
// actually present in the archive (a truncated bundle).
func TestUntarGzTruncatedEntry(t *testing.T) {
	t.Parallel()

	src := filepath.Join(t.TempDir(), "truncated.tar.gz")
	f, err := os.Create(src)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "big.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 100,
	}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := tw.Write([]byte("short")); err != nil {
		t.Fatalf("write short body: %v", err)
	}
	// Deliberately skip tw.Close() — truncated archive.
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}

	if err := untarGz(src, t.TempDir()); err == nil {
		t.Fatal("untarGz of a truncated tar entry should fail")
	}
}

// TestUntarGzMkdirAllFailure exercises untarGz's os.MkdirAll failure path: a
// tar entry nested under a path component that already exists as a regular
// file in dstDir, so MkdirAll(dst's parent) fails.
func TestUntarGzMkdirAllFailure(t *testing.T) {
	t.Parallel()

	src := filepath.Join(t.TempDir(), "nested.tar.gz")
	f, err := os.Create(src)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	body := "x"
	if err := tw.WriteHeader(&tar.Header{
		Name: "blocked/inner.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body)),
	}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
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

	dst := t.TempDir()
	// Pre-create "blocked" as a regular FILE so MkdirAll(dst/blocked) fails.
	if err := os.WriteFile(filepath.Join(dst, "blocked"), []byte("i am a file"), 0o644); err != nil {
		t.Fatalf("premake blocked as a file: %v", err)
	}

	if err := untarGz(src, dst); err == nil {
		t.Fatal("untarGz should fail when the entry's parent dir is blocked by an existing file")
	}
}

// TestUntarGzOpenFileFailure exercises untarGz's os.OpenFile failure path: the
// destination path already exists as a DIRECTORY, so opening it for write
// (O_WRONLY|O_CREATE|O_TRUNC) fails.
func TestUntarGzOpenFileFailure(t *testing.T) {
	t.Parallel()

	src := filepath.Join(t.TempDir(), "collide.tar.gz")
	f, err := os.Create(src)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	body := "x"
	if err := tw.WriteHeader(&tar.Header{
		Name: "collide.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body)),
	}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
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

	dst := t.TempDir()
	// Pre-create "collide.txt" as a DIRECTORY so OpenFile for write fails.
	if err := os.MkdirAll(filepath.Join(dst, "collide.txt"), 0o755); err != nil {
		t.Fatalf("premake collide.txt as a dir: %v", err)
	}

	if err := untarGz(src, dst); err == nil {
		t.Fatal("untarGz should fail when the destination path exists as a directory")
	}
}

// TestTarGzDirSkipsDirsAndPreservesFileContent verifies tarGzDir walks a
// source tree, skips directory entries themselves (only files get tar
// headers), and preserves file content through a full tar/untar round trip.
func TestTarGzDirSkipsDirsAndPreservesFileContent(t *testing.T) {
	t.Parallel()

	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "top.txt"), []byte("top-level"), 0o644); err != nil {
		t.Fatalf("write top.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "nested.txt"), []byte("nested-content"), 0o644); err != nil {
		t.Fatalf("write nested.txt: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "out.tar.gz")
	if err := tarGzDir(src, dst); err != nil {
		t.Fatalf("tarGzDir: %v", err)
	}

	out := t.TempDir()
	if err := untarGz(dst, out); err != nil {
		t.Fatalf("untarGz: %v", err)
	}
	top, err := os.ReadFile(filepath.Join(out, "top.txt"))
	if err != nil || string(top) != "top-level" {
		t.Fatalf("top.txt = %q, %v", top, err)
	}
	nested, err := os.ReadFile(filepath.Join(out, "sub", "nested.txt"))
	if err != nil || string(nested) != "nested-content" {
		t.Fatalf("sub/nested.txt = %q, %v", nested, err)
	}
}
