package baseline

// since_deploy_gitref_test.go — DD-GITREF-1: .git/HEAD and a ".git" gitdir
// file are attacker-controllable when `dsd health --since-deploy` is run
// (often as root) from a hostile checkout. These tests pin that neither can
// steer the plumbing reader outside <gitDir>/refs/... and
// <gitDir>/objects/<hex>, and that no error echoes file content.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hostileRepo builds root/{secret, a/b/.git/} and returns (root, repo, gitDir).
// "secret" holds the sha of a real loose commit in gitDir, so that if a
// traversal is followed the whole chain succeeds and gitLastCommitTime returns
// a time instead of an error: a traversal can't hide behind a later failure.
func hostileRepo(t *testing.T, head string) (root, repo, gitDir string) {
	t.Helper()
	root = t.TempDir()
	repo = filepath.Join(root, "a", "b")
	gitDir = filepath.Join(repo, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sha := writeLooseCommit(t, gitDir, 1700000000)
	if err := os.WriteFile(filepath.Join(root, "secret"), []byte(sha+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(head), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, repo, gitDir
}

func TestResolveHEAD_RejectsHostileRef(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ref  func(root string) string
	}{
		{"dotdot to sibling file", func(string) string { return "../../../secret" }},
		{"dotdot to etc passwd", func(string) string { return "../../../../../../../../etc/passwd" }},
		{"dotdot after refs prefix", func(string) string { return "refs/../../../../secret" }},
		{"dotdot component inside refs", func(string) string { return "refs/heads/../../x" }},
		{"absolute path", func(r string) string { return filepath.Join(r, "secret") }},
		{"no refs prefix", func(string) string { return "HEAD" }},
		{"backslash", func(string) string { return `refs\heads\main` }},
		{"empty component", func(string) string { return "refs//heads/main" }},
		{"trailing slash", func(string) string { return "refs/heads/" }},
		{"control char", func(string) string { return "refs/heads/ma\x01in" }},
		{"space", func(string) string { return "refs/heads/ma in" }},
		{"bare refs/", func(string) string { return "refs/" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			// The root is only known after hostileRepo, so write HEAD in two steps.
			root, repo, gitDir := hostileRepo(t, "placeholder\n")
			ref := c.ref(root)
			if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: "+ref+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := gitLastCommitTime(repo)
			if err == nil {
				t.Fatalf("gitLastCommitTime followed hostile ref %q and returned %v", ref, got)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "etc/passwd") {
				t.Errorf("error echoes the ref text: %v", err)
			}
		})
	}
}

// TestResolveHEAD_HostileRefFileContentNotLeaked: the traversal target holds
// text that is not a sha; its bytes must never reach the error.
func TestResolveHEAD_HostileRefFileContentNotLeaked(t *testing.T) {
	t.Parallel()
	root, repo, _ := hostileRepo(t, "ref: ../../../secret\n")
	const marker = "root:x:0:0:SENTINEL-DO-NOT-LEAK"
	if err := os.WriteFile(filepath.Join(root, "secret"), []byte(marker+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := gitLastCommitTime(repo)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), "root:x") {
		t.Errorf("error leaks file content: %v", err)
	}
}

func TestResolvePackedRef_RejectsUnvalidatedRef(t *testing.T) {
	t.Parallel()
	gitDir := t.TempDir()
	sha := strings.Repeat("d", 40)
	packed := sha + " ../../x\n" + sha + " refs/heads/main\n"
	if err := os.WriteFile(filepath.Join(gitDir, "packed-refs"), []byte(packed), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolvePackedRef(gitDir, "../../x"); err == nil {
		t.Error("resolvePackedRef accepted an unvalidated ref")
	}
	if got, err := resolvePackedRef(gitDir, "refs/heads/main"); err != nil || got != sha {
		t.Errorf("resolvePackedRef(valid) = %q, %v", got, err)
	}
}

func TestValidRefName(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"refs/heads/main", "refs/heads/feature/x-1.2", "refs/remotes/origin/main", "refs/tags/v1.0.0"} {
		if !validRefName(ok) {
			t.Errorf("validRefName(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{
		"", "refs", "refs/", "/refs/heads/main", "refs/heads/..", "refs/../x", "refs/./x",
		"refs/heads/a..b", "refs/heads/x.lock", "refs/heads/x/", `refs\x`, "refs/a\x00b", "refs/a\nb",
		"refs/a~b", "refs/a^b", "refs/a:b", "refs/a?b", "refs/a*b", "refs/a[b", "refs/a@{b",
		"refs/" + strings.Repeat("a", 2000),
	} {
		if validRefName(bad) {
			t.Errorf("validRefName(%q) = true, want false", bad)
		}
	}
}

func TestGitLastCommitTime_LooseRefInNestedBranch(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	gitDir := filepath.Join(repo, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads", "feature"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/feature/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sha := writeLooseCommit(t, gitDir, 1710000000)
	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "feature", "x"), []byte(sha+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := gitLastCommitTime(repo)
	if err != nil || got.Unix() != 1710000000 {
		t.Fatalf("got %v, %v", got, err)
	}
}
