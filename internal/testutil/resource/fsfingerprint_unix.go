//go:build unix

package resource

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"
)

// Fingerprint captures a byte-for-byte identity of the directory tree rooted at
// dir: for every entry (files, dirs, symlinks) the relative path, type, size,
// mode, mtime (nanosecond), inode and, for regular files, the content hash and,
// for symlinks, the link target. Two trees with the same Fingerprint are
// identical for the purposes of the read-only claim: no file created, removed,
// resized, re-timestamped, re-permissioned, re-inode'd or rewritten.
//
// It uses Lstat (never follows symlinks) so a planted symlink is recorded as a
// symlink, and reads regular-file content so an in-place rewrite that preserves
// size and mtime is still caught. It does NOT capture xattrs, ACLs, or
// sub-second clock skew beyond the stored mtime nanoseconds; it does not detect
// a file that was written and restored identically within one run (that is a
// write the claim still forbids, but this oracle cannot see it — stated so the
// guarantee is not overclaimed).
func Fingerprint(t testing.TB, dir string) string {
	t.Helper()
	type entry struct {
		rel   string
		kind  string
		size  int64
		mode  fs.FileMode
		mtime int64
		ino   uint64
		extra string // content hash for files, link target for symlinks
	}
	var entries []entry
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return rerr
		}
		fi, lerr := os.Lstat(path)
		if lerr != nil {
			return lerr
		}
		e := entry{rel: rel, size: fi.Size(), mode: fi.Mode(), mtime: fi.ModTime().UnixNano()}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			e.ino = uint64(st.Ino)
		}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			e.kind = "symlink"
			tgt, _ := os.Readlink(path)
			e.extra = tgt
		case fi.IsDir():
			e.kind = "dir"
		case fi.Mode().IsRegular():
			e.kind = "file"
			data, rerr := os.ReadFile(path) // #nosec G304 -- test-controlled temp tree
			if rerr == nil {
				sum := sha256.Sum256(data)
				e.extra = fmt.Sprintf("%x", sum[:8])
			} else {
				e.extra = "unreadable:" + rerr.Error()
			}
		default:
			e.kind = fmt.Sprintf("other(%s)", fi.Mode().Type())
		}
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		t.Fatalf("fingerprinting %s: %v", dir, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })

	h := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(h, "%s\x00%s\x00%d\x00%o\x00%d\x00%d\x00%s\n",
			e.rel, e.kind, e.size, e.mode, e.mtime, e.ino, e.extra)
	}
	return fmt.Sprintf("%d-entries-%x", len(entries), h.Sum(nil))
}

// AssertUnchanged fails the test if dir's Fingerprint differs from before. It is
// the read-only-claim oracle for a target that points HOME/TMPDIR/cwd at an
// empty temp dir: run the fuzzed code, then assert the tree is byte-identical.
func AssertUnchanged(t testing.TB, dir, before string) {
	t.Helper()
	after := Fingerprint(t, dir)
	if after != before {
		t.Fatalf("read-only claim violated: directory tree under %s changed\n  before: %s\n  after:  %s", dir, before, after)
	}
}
