package source

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func writeTarGz(t *testing.T, names ...string) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "in.tar.gz")
	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	body := "payload"
	for _, name := range names {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return src
}

// Zip Slip: names that escape via an inner "..", and that only look like
// "..", must be handled exactly: escapes are skipped, nothing lands outside
// dst, and a legitimate name that merely starts with ".." is extracted.
func TestUntarGz_ZipSlipNames(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	dst := filepath.Join(parent, "dst")
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	src := writeTarGz(t,
		"a/../../escape1.txt",
		"../escape2.txt",
		"/abs-escape3.txt",
		"a/b/../../../escape4.txt",
		"ok/nested.txt",
		"..hidden.txt",
	)
	if err := untarGz(src, dst); err != nil {
		t.Fatalf("untarGz: %v", err)
	}
	for _, n := range []string{"escape1.txt", "escape2.txt", "escape4.txt"} {
		if _, err := os.Stat(filepath.Join(parent, n)); err == nil {
			t.Errorf("%s escaped dst", n)
		}
	}
	for _, n := range []string{"ok/nested.txt", "..hidden.txt"} {
		if _, err := os.Stat(filepath.Join(dst, n)); err != nil {
			t.Errorf("legitimate entry %s not extracted: %v", n, err)
		}
	}
}

// Defence in depth: even if dst already contains a symlink that points
// outside (the tar itself never creates one), an entry through it is refused
// rather than written to the link target.
func TestUntarGz_RefusesWriteThroughSymlinkOutOfDst(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	outside := filepath.Join(parent, "outside")
	dst := filepath.Join(parent, "dst")
	for _, d := range []string{outside, dst} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(dst, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	src := writeTarGz(t, "link/pwned.txt")
	if err := untarGz(src, dst); err == nil {
		t.Error("expected an error writing through a symlink that leaves dst")
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned.txt")); err == nil {
		t.Error("entry was written through the symlink, outside dst")
	}
}
