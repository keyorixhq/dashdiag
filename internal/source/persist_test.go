package source

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// chmodRestoring chmods path and registers a cleanup that restores the
// original mode — needed because t.TempDir()'s own cleanup can fail to
// remove a directory tree containing unwritable entries.
func chmodRestoring(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	orig := fi.Mode()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(path, orig)
	})
}

// TestSaveMkdirAllFailure exercises Save's os.MkdirAll failure path: dir has a
// path component ("files") that already exists as a REGULAR FILE, so
// MkdirAll(dir/files/blobs) cannot create the intermediate directory.
func TestSaveMkdirAllFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "files"), []byte("i am a file, not a dir"), 0o644); err != nil {
		t.Fatalf("premake files as a plain file: %v", err)
	}

	b := NewBundle()
	if err := b.Save(dir); err == nil {
		t.Fatal("Save should fail when 'files' exists as a regular file blocking MkdirAll")
	}
}

// TestSaveIndexWriteFailures exercises each of Save's top-level index-file
// write failures (files/index.json, globs.json, dirs.json, links.json,
// stats.json) by pre-creating the target path AS A DIRECTORY, so os.WriteFile
// fails with "is a directory" while every earlier step (manifest, blobs)
// still succeeds.
func TestSaveIndexWriteFailures(t *testing.T) {
	t.Parallel()

	targets := []string{
		"files/index.json",
		"globs.json",
		"dirs.json",
		"links.json",
		"stats.json",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "files/blobs"), 0o755); err != nil {
				t.Fatalf("premkdir files/blobs: %v", err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "commands/blobs"), 0o755); err != nil {
				t.Fatalf("premkdir commands/blobs: %v", err)
			}
			if err := os.MkdirAll(filepath.Join(dir, target), 0o755); err != nil {
				t.Fatalf("pre-create %s as a directory: %v", target, err)
			}

			b := NewBundle()
			if err := b.Save(dir); err == nil {
				t.Fatalf("Save should fail writing %s when it exists as a directory", target)
			}
		})
	}
}

// TestSaveManifestWriteFailure exercises the manifest.json write-failure path:
// the files/blobs and commands/blobs subdirs already exist (so MkdirAll is a
// no-op), but the bundle root itself is read-only, so writeJSON(manifest.json)
// fails.
func TestSaveManifestWriteFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "files/blobs"), 0o755); err != nil {
		t.Fatalf("premkdir files/blobs: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "commands/blobs"), 0o755); err != nil {
		t.Fatalf("premkdir commands/blobs: %v", err)
	}
	chmodRestoring(t, dir, 0o555)

	b := NewBundle()
	if err := b.Save(dir); err == nil {
		t.Fatal("Save into a read-only root should fail writing manifest.json")
	}
}

// TestSaveBlobWriteFailure exercises the file-blob write-failure path: the
// bundle root and index files are writable, but files/blobs itself is
// read-only, so writing the recorded file's blob content fails.
func TestSaveBlobWriteFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "files/blobs"), 0o755); err != nil {
		t.Fatalf("premkdir files/blobs: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "commands/blobs"), 0o755); err != nil {
		t.Fatalf("premkdir commands/blobs: %v", err)
	}
	chmodRestoring(t, filepath.Join(dir, "files/blobs"), 0o555)

	b := NewBundle()
	b.PutFile("/etc/present", []byte("data"))
	if err := b.Save(dir); err == nil {
		t.Fatal("Save should fail writing a file blob into a read-only files/blobs dir")
	}
}

// TestSaveCommandBlobWriteFailure exercises the stdout/stderr command-blob
// write-failure paths: commands/blobs is read-only.
func TestSaveCommandBlobWriteFailure(t *testing.T) {
	t.Parallel()

	t.Run("stdout blob", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "files/blobs"), 0o755); err != nil {
			t.Fatalf("premkdir files/blobs: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "commands/blobs"), 0o755); err != nil {
			t.Fatalf("premkdir commands/blobs: %v", err)
		}
		chmodRestoring(t, filepath.Join(dir, "commands/blobs"), 0o555)

		b := NewBundle()
		b.putCmd("mytool", []string{"-x"}, Result{Stdout: []byte("out")}, nil)
		if err := b.Save(dir); err == nil {
			t.Fatal("Save should fail writing the stdout blob into a read-only commands/blobs dir")
		}
	})

	// The stderr-blob write is a separate statement from the stdout-blob write
	// (Save writes stdout first, then stderr) — a directory-wide read-only
	// commands/blobs would hit the stdout write first whenever both are
	// present, never isolating the stderr write. Instead pre-create the exact
	// stderr blob filename Save will choose (commands/blobs/0000.err) AS A
	// DIRECTORY, so the stdout blob write succeeds (0000.out is free) and only
	// the stderr write collides.
	t.Run("stderr blob", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "files/blobs"), 0o755); err != nil {
			t.Fatalf("premkdir files/blobs: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "commands/blobs/0000.err"), 0o755); err != nil {
			t.Fatalf("premake stderr blob path as a dir: %v", err)
		}

		b := NewBundle()
		b.putCmd("mytool", []string{"-x"}, Result{Stdout: []byte("out"), Stderr: []byte("err")}, nil)
		if err := b.Save(dir); err == nil {
			t.Fatal("Save should fail writing the stderr blob when its path exists as a directory")
		}
	})
}

// TestLoadManifestErrors exercises Load's manifest-read and format-mismatch
// failure paths.
func TestLoadManifestErrors(t *testing.T) {
	t.Parallel()

	t.Run("missing manifest", func(t *testing.T) {
		t.Parallel()
		if _, err := Load(t.TempDir()); err == nil {
			t.Fatal("Load of a dir with no manifest.json should fail")
		}
	})

	t.Run("format mismatch", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := writeJSON(filepath.Join(dir, "manifest.json"), Manifest{Format: "raw-v0-ancient"}); err != nil {
			t.Fatalf("writeJSON manifest: %v", err)
		}
		_, err := Load(dir)
		if err == nil {
			t.Fatal("Load should reject a bundle with a mismatched format version")
		}
	})
}

// TestLoadFileIndexMissing exercises Load's files/index.json read-failure path
// — a manifest with the right format but no files/index.json.
func TestLoadFileIndexMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := writeJSON(filepath.Join(dir, "manifest.json"), Manifest{Format: FormatVersion}); err != nil {
		t.Fatalf("writeJSON manifest: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load should fail when files/index.json is missing")
	}
}

// TestLoadFileBlobMissing exercises Load's per-file blob-read-failure path —
// the index references a blob file that was never written.
func TestLoadFileBlobMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o755); err != nil {
		t.Fatalf("premkdir files: %v", err)
	}
	if err := writeJSON(filepath.Join(dir, "manifest.json"), Manifest{Format: FormatVersion}); err != nil {
		t.Fatalf("writeJSON manifest: %v", err)
	}
	fidx := []fileIndexEntry{{Path: "/etc/ghost", Blob: "files/blobs/9999"}}
	if err := writeJSON(filepath.Join(dir, "files/index.json"), fidx); err != nil {
		t.Fatalf("writeJSON files/index.json: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load should fail when an indexed blob file is missing")
	}
}

// TestLoadCommandIndexMissing exercises Load's commands/index.json
// read-failure path — everything else present and valid, but the command
// index itself is absent.
func TestLoadCommandIndexMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o755); err != nil {
		t.Fatalf("premkdir files: %v", err)
	}
	if err := writeJSON(filepath.Join(dir, "manifest.json"), Manifest{Format: FormatVersion}); err != nil {
		t.Fatalf("writeJSON manifest: %v", err)
	}
	if err := writeJSON(filepath.Join(dir, "files/index.json"), []fileIndexEntry{}); err != nil {
		t.Fatalf("writeJSON files/index.json: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load should fail when commands/index.json is missing")
	}
}

// TestLoadCommandBlobsMissingAreIgnored verifies Load's stdout/stderr blob
// reads for a command entry use the errors-ignored os.ReadFile pattern (a
// missing blob file yields empty bytes, not a Load failure) — this documents
// the actual (lenient) behaviour of that code path.
func TestLoadCommandBlobsMissingAreIgnored(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o755); err != nil {
		t.Fatalf("premkdir files: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "commands"), 0o755); err != nil {
		t.Fatalf("premkdir commands: %v", err)
	}
	if err := writeJSON(filepath.Join(dir, "manifest.json"), Manifest{Format: FormatVersion}); err != nil {
		t.Fatalf("writeJSON manifest: %v", err)
	}
	if err := writeJSON(filepath.Join(dir, "files/index.json"), []fileIndexEntry{}); err != nil {
		t.Fatalf("writeJSON files/index.json: %v", err)
	}
	cidx := []cmdIndexEntry{{
		Argv:       []string{"ghost-tool"},
		StdoutBlob: "commands/blobs/missing.out",
		StderrBlob: "commands/blobs/missing.err",
	}}
	if err := writeJSON(filepath.Join(dir, "commands/index.json"), cidx); err != nil {
		t.Fatalf("writeJSON commands/index.json: %v", err)
	}

	b, err := Load(dir)
	if err != nil {
		t.Fatalf("Load should tolerate missing command blob files, got: %v", err)
	}
	rec, ok := b.getCmd("ghost-tool", nil)
	if !ok {
		t.Fatal("command entry should still be present despite missing blobs")
	}
	if len(rec.res.Stdout) != 0 || len(rec.res.Stderr) != 0 {
		t.Fatalf("expected empty stdout/stderr for missing blobs, got %+v", rec.res)
	}
}

// TestSaveManifestWriteFailureRootSafe covers persist.go:61-63 without relying
// on directory permissions (chmod), so it also passes when the test runs as
// root.  Pre-creating manifest.json as a directory makes os.WriteFile fail
// even for root.
func TestSaveManifestWriteFailureRootSafe(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "files/blobs"), 0o755); err != nil {
		t.Fatalf("premkdir files/blobs: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "commands/blobs"), 0o755); err != nil {
		t.Fatalf("premkdir commands/blobs: %v", err)
	}
	// Pre-create manifest.json as a DIRECTORY so os.WriteFile always fails,
	// even when the test process is root.
	if err := os.MkdirAll(filepath.Join(dir, "manifest.json"), 0o755); err != nil {
		t.Fatalf("premkdir manifest.json as dir: %v", err)
	}

	b := NewBundle()
	if err := b.Save(dir); err == nil {
		t.Fatal("Save should fail when manifest.json exists as a directory")
	}
}

// TestSaveBlobWriteFailureRootSafe covers persist.go:74-76 without relying on
// directory permissions: pre-creating the exact blob path Save would choose
// (files/blobs/0000) as a directory makes os.WriteFile fail even as root.
func TestSaveBlobWriteFailureRootSafe(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "files/blobs/0000"), 0o755); err != nil {
		t.Fatalf("premkdir files/blobs/0000 as dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "commands/blobs"), 0o755); err != nil {
		t.Fatalf("premkdir commands/blobs: %v", err)
	}

	b := NewBundle()
	b.PutFile("/etc/present", []byte("data"))
	if err := b.Save(dir); err == nil {
		t.Fatal("Save should fail when files/blobs/0000 exists as a directory")
	}
}

// TestSaveStdoutBlobWriteFailureRootSafe covers persist.go:106-108 without
// relying on directory permissions: pre-creating the exact stdout blob path
// Save would choose (commands/blobs/0000.out) as a directory makes
// os.WriteFile fail even as root.
func TestSaveStdoutBlobWriteFailureRootSafe(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "files/blobs"), 0o755); err != nil {
		t.Fatalf("premkdir files/blobs: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "commands/blobs/0000.out"), 0o755); err != nil {
		t.Fatalf("premkdir commands/blobs/0000.out as dir: %v", err)
	}

	b := NewBundle()
	b.putCmd("mytool", []string{"-x"}, Result{Stdout: []byte("out")}, nil)
	if err := b.Save(dir); err == nil {
		t.Fatal("Save should fail when commands/blobs/0000.out exists as a directory")
	}
}

// TestSaveLoadFullRoundTripWithLinksStatsStatfs exercises Save/Load across
// every section (files, globs, dirs, links, stats, statfs, commands) in one
// pass, verifying saveInlineMeta and its Load counterpart end to end.
func TestSaveLoadFullRoundTripWithLinksStatsStatfs(t *testing.T) {
	t.Parallel()

	b := NewBundle()
	b.PutFile("/etc/present", []byte("hello"))
	b.PutDir("/etc/present.d", []string{"a", "b"})
	b.PutGlob("/etc/present.d/*", []string{"/etc/present.d/a", "/etc/present.d/b"})
	b.putLink("/etc/alt", "/etc/present", nil)
	b.putStat("/etc/present", FileMeta{Size: 5}, nil)
	b.putStatfs("/mnt/data", StatfsInfo{Blocks: 100, Bsize: 4096}, nil)
	b.PutCmd("uptime", nil, "up 3 days\n", 0)

	dir := t.TempDir()
	if err := b.Save(dir); err != nil {
		t.Fatalf("save: %v", err)
	}
	b2, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	rp := NewReplay(b2)
	if got, err := rp.ReadFile("/etc/present"); err != nil || string(got) != "hello" {
		t.Fatalf("ReadFile = %q, %v", got, err)
	}
	if got, err := rp.ReadDir("/etc/present.d"); err != nil || len(got) != 2 {
		t.Fatalf("ReadDir = %v, %v", got, err)
	}
	if got, err := rp.Glob("/etc/present.d/*"); err != nil || len(got) != 2 {
		t.Fatalf("Glob = %v, %v", got, err)
	}
	if got, err := rp.Readlink("/etc/alt"); err != nil || got != "/etc/present" {
		t.Fatalf("Readlink = %q, %v", got, err)
	}
	if got, err := rp.Stat("/etc/present"); err != nil || got.Size != 5 {
		t.Fatalf("Stat = %+v, %v", got, err)
	}
	if got, err := rp.Statfs("/mnt/data"); err != nil || got.Blocks != 100 {
		t.Fatalf("Statfs = %+v, %v", got, err)
	}
	if res, err := rp.Run(context.Background(), "uptime"); err != nil || string(res.Stdout) != "up 3 days\n" {
		t.Fatalf("Run = %+v, %v", res, err)
	}
}
