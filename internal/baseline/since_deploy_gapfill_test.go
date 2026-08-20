package baseline

// since_deploy_gapfill_test.go — closes real coverage gaps found by a full
// coverage audit: findGitDir's worktree/submodule "gitdir:" file branch (a
// real .git checkout layout, distinct from every existing test which only
// uses a plain .git directory), resolvePackedRef's "ref not found" branch,
// and SafeHostname (baseline.go) which had no direct test of its own.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFindGitDir_WorktreeGitFile covers the "gitdir: <path>" branch: in a
// git worktree or submodule checkout, .git is a FILE (not a directory)
// pointing at the real git dir elsewhere. No existing test exercises this —
// every other gitLastCommitTime test uses a plain .git directory.
func TestFindGitDir_WorktreeGitFile(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	realGitDir := filepath.Join(t.TempDir(), "real-gitdir")
	if err := os.MkdirAll(realGitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git"), []byte("gitdir: "+realGitDir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := findGitDir(repo)
	if err != nil {
		t.Fatalf("findGitDir: %v", err)
	}
	if got != realGitDir {
		t.Errorf("findGitDir() = %q, want %q", got, realGitDir)
	}
}

// TestFindGitDir_WalksUpFromSubdirectory covers the parent-directory walk:
// .git lives at the repo root, but findGitDir is called from a subdirectory
// (the common case — dsd health --since-deploy runs from wherever the
// operator happens to be, not necessarily the repo root).
func TestFindGitDir_WalksUpFromSubdirectory(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	gitDir := filepath.Join(repo, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(repo, "a", "b", "c")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := findGitDir(sub)
	if err != nil {
		t.Fatalf("findGitDir: %v", err)
	}
	if got != gitDir {
		t.Errorf("findGitDir() = %q, want %q", got, gitDir)
	}
}

// TestResolvePackedRef_RefNotFound covers packed-refs existing but not
// containing the requested ref — distinct from the file-missing case
// (resolveHEAD falling through to resolvePackedRef in the first place) that
// TestGitLastCommitTime_NoGitDir/PackedCommit already exercise indirectly.
func TestResolvePackedRef_RefNotFound(t *testing.T) {
	t.Parallel()
	gitDir := t.TempDir()
	packed := "# pack-refs with: peeled fully-peeled sorted\n" +
		strings.Repeat("a", 40) + " refs/heads/other\n"
	if err := os.WriteFile(filepath.Join(gitDir, "packed-refs"), []byte(packed), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := resolvePackedRef(gitDir, "refs/heads/main"); err == nil {
		t.Error("resolvePackedRef() = nil error, want an error when the ref isn't in packed-refs")
	}
}

// TestSafeHostname covers every branch directly — no existing test called it
// on its own before this (only indirectly, via SaveBaseline/SaveGolden with
// already-safe hostnames). Security-relevant: hostname is attacker-controlled
// on a replayed bundle's manifest (see SafeHostname's own doc comment).
func TestSafeHostname(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"clean name passes through", "web01", "web01"},
		{"empty becomes unknown-host", "", "unknown-host"},
		{"dot becomes unknown-host", ".", "unknown-host"},
		{"dot-dot becomes unknown-host", "..", "unknown-host"},
		{"forward slash replaced", "a/b", "a_b"},
		{"backslash replaced", `a\b`, "a_b"},
		{"colon replaced", "a:b", "a_b"},
		{"NUL byte replaced", "a\x00b", "a_b"},
		{"path traversal neutralized", "../../etc/passwd", ".._.._etc_passwd"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := SafeHostname(c.in); got != c.want {
				t.Errorf("SafeHostname(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestResolvePackedRef_SkipsCommentsAndPeeledLines covers the "#"/"^"
// line-skipping branches alongside a real match, so the skip logic is
// verified to actually let the real ref through, not just avoid crashing.
func TestResolvePackedRef_SkipsCommentsAndPeeledLines(t *testing.T) {
	t.Parallel()
	gitDir := t.TempDir()
	wantSHA := strings.Repeat("b", 40)
	packed := "# pack-refs with: peeled fully-peeled sorted\n" +
		wantSHA + " refs/heads/main\n" +
		"^" + strings.Repeat("c", 40) + "\n"
	if err := os.WriteFile(filepath.Join(gitDir, "packed-refs"), []byte(packed), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := resolvePackedRef(gitDir, "refs/heads/main")
	if err != nil {
		t.Fatalf("resolvePackedRef: %v", err)
	}
	if got != wantSHA {
		t.Errorf("resolvePackedRef() = %q, want %q", got, wantSHA)
	}
}
