package source

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// This file fuzzes the two entry points that ingest a capture bundle from
// another party's machine — the least trusted input this package handles.
// LoadTarball is reached from `dsd replay`/`dsd diff` on a tarball a customer
// or fleet host handed over; Load is its unpacked-directory counterpart. The
// property under test is not "doesn't panic" but "extraction/parsing never
// escapes its own scratch directory", regardless of success or failure.

type tarEntry struct {
	name     string
	body     string
	typeflag byte
}

func gzipBytes(data []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return buf.Bytes()
}

func tarballOf(entries ...tarEntry) []byte {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		_ = tw.WriteHeader(&tar.Header{
			Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tf,
		})
		_, _ = tw.Write([]byte(e.body))
	}
	_ = tw.Close()
	return gzipBytes(raw.Bytes())
}

func buildValidBundleTarball(tb testing.TB) []byte {
	tb.Helper()
	b := NewBundle()
	b.files["etc/hostname"] = fileRec{data: []byte("fuzz-seed-host\n")}
	dir := tb.TempDir()
	out := filepath.Join(dir, "seed.tar.gz")
	if err := b.SaveTarball(out); err != nil {
		tb.Fatalf("building valid seed bundle: %v", err)
	}
	data, err := os.ReadFile(out) // #nosec G304 -- fixed path this test just wrote
	if err != nil {
		tb.Fatalf("reading valid seed bundle: %v", err)
	}
	return data
}

type dirSnapshotEntry struct {
	path string
	mode fs.FileMode
}

// snapshotDir lists every entry under root (relative paths + mode, using
// Lstat semantics via fs.DirEntry.Type so a symlink is reported as a symlink
// rather than dereferenced) so a fuzz iteration can diff before/after state
// instead of trusting that extraction cleaned up after itself.
func snapshotDir(t *testing.T, root string) []dirSnapshotEntry {
	t.Helper()
	var out []dirSnapshotEntry
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		out = append(out, dirSnapshotEntry{path: rel, mode: d.Type()})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %q: %v", root, err)
	}
	return out
}

// FuzzLoadTarball fuzzes LoadTarball(path) against attacker-controlled tarball
// bytes. LoadTarball manages its own scratch directory via os.MkdirTemp("",
// "dsd-raw-*") and always removes it before returning (success or error) —
// pointing TMPDIR at a directory this test owns lets it assert that promise
// holds for hostile input: no leftover file, directory, or symlink anywhere
// under TMPDIR once the call returns.
func FuzzLoadTarball(f *testing.F) {
	if data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "captures", "amd-ubuntu2604-20260617", "dsd-nonroot.tar.gz")); err == nil { // #nosec G304 -- fixed repo-relative fixture path
		f.Add(data)
	}
	f.Add(buildValidBundleTarball(f))

	f.Add([]byte{})
	f.Add([]byte("not a gzip stream at all"))
	f.Add(gzipBytes([]byte("valid gzip, but the payload is not a tar archive")))
	f.Add(gzipBytes(nil))
	f.Add(tarballOf(tarEntry{name: "../../etc/passwd", body: "pwned"}))
	f.Add(tarballOf(tarEntry{name: "/etc/passwd", body: "pwned"}))
	f.Add(tarballOf(tarEntry{name: "a/../../b", body: "x"}))
	f.Add(tarballOf(tarEntry{name: "dup.txt", body: "first"}, tarEntry{name: "dup.txt", body: "second"}))
	f.Add(tarballOf(tarEntry{name: "zero.txt", body: ""}))
	f.Add(tarballOf(tarEntry{name: "link", typeflag: tar.TypeSymlink, body: ""}))
	f.Add(tarballOf(tarEntry{name: "dev", typeflag: tar.TypeChar, body: ""}))
	f.Add(tarballOf(tarEntry{name: "manifest.json", body: `{"format":"raw-v1"`}))
	f.Add(tarballOf(tarEntry{name: "nested.tar.gz", body: string(tarballOf(tarEntry{name: "inner.txt", body: "x"}))}))
	{
		many := make([]tarEntry, 0, 300)
		for i := range 300 {
			many = append(many, tarEntry{name: filepath.Join("many", string(rune('a'+i%26)), "f"), body: "x"})
		}
		f.Add(tarballOf(many...))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpRoot := t.TempDir()
		t.Setenv("TMPDIR", tmpRoot)

		srcDir := t.TempDir()
		src := filepath.Join(srcDir, "fuzz.tar.gz")
		if err := os.WriteFile(src, data, 0o600); err != nil { // #nosec G306 -- fixed path under this test's own temp dir
			t.Fatalf("writing fuzz tarball to disk: %v", err)
		}

		before := snapshotDir(t, tmpRoot)
		_, _ = LoadTarball(src) // success or error are both fine — leakage is not

		after := snapshotDir(t, tmpRoot)
		if len(after) != len(before) {
			t.Fatalf("LoadTarball left %d filesystem entries under TMPDIR after returning (had %d before): %v", len(after), len(before), after)
		}
		for _, e := range after {
			if e.mode&fs.ModeSymlink != 0 {
				t.Fatalf("LoadTarball created a symlink at %q", e.path)
			}
		}
	})
}

// FuzzLoad fuzzes Load(dir) against an attacker-controlled files/index.json —
// the on-disk JSON index whose Blob field feeds safeBlobJoin, the guard that
// is supposed to stop a crafted bundle from making Load read a file outside
// the bundle directory. manifest.json and commands/index.json are held fixed
// and valid so every fuzz iteration actually reaches the index parser instead
// of bailing out at the format-version gate. The bundle directory always
// lives at <parent>/bundle so a traversal payload of "../canary.txt" reaches
// a fixed, known secret file at <parent>/canary.txt regardless of the
// fuzz-generated content — if Load ever surfaces that content, safeBlobJoin's
// guard has been bypassed.
func FuzzLoad(f *testing.F) {
	seeds := [][]byte{
		[]byte(`[]`),
		[]byte(`[{"path":"a","blob":"files/blobs/0000"}]`),
		[]byte(`[{"path":"a","blob":"../canary.txt"}]`),
		[]byte(`[{"path":"a","blob":"../../canary.txt"}]`),
		[]byte(`[{"path":"a","blob":"/etc/passwd"}]`),
		[]byte(`[{"path":"a","blob":""}]`),
		[]byte(`[{"path":"a","not_exist":true}]`),
		[]byte(`[{"path":"a","perm":true}]`),
		[]byte(`not even json`),
		[]byte(`{"not":"an array"}`),
		[]byte(`[{"path":"a","blob":"files/blobs/0000/../../../canary.txt"}]`),
		[]byte(`[{"path":"a","blob":"files/blobs/../../canary.txt"}]`),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, fileIndex []byte) {
		parent := t.TempDir()
		dir := filepath.Join(parent, "bundle")
		if err := os.MkdirAll(filepath.Join(dir, "files/blobs"), 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "commands"), 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}

		canary := []byte("SECRET-CANARY-OUTSIDE-BUNDLE-DIR")
		if err := os.WriteFile(filepath.Join(parent, "canary.txt"), canary, 0o600); err != nil {
			t.Fatalf("writing canary: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "files", "blobs", "0000"), []byte("legit-blob-content"), 0o600); err != nil {
			t.Fatalf("writing legit blob: %v", err)
		}
		if err := writeJSON(filepath.Join(dir, "manifest.json"), Manifest{Format: FormatVersion}); err != nil {
			t.Fatalf("writing manifest.json: %v", err)
		}
		if err := writeJSON(filepath.Join(dir, "commands/index.json"), []cmdIndexEntry{}); err != nil {
			t.Fatalf("writing commands/index.json: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "files", "index.json"), fileIndex, 0o600); err != nil {
			t.Fatalf("writing files/index.json: %v", err)
		}

		b, err := Load(dir)
		if err != nil {
			return // rejecting a hostile/malformed index is the correct, safe outcome
		}
		for path, rec := range b.files {
			if bytes.Equal(rec.data, canary) {
				t.Fatalf("Load(%q) surfaced the canary file from outside the bundle directory into file entry %q — safeBlobJoin traversal guard bypassed", dir, path)
			}
		}
	})
}
