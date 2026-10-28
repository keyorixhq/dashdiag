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

// Item 3: the "gitdir: <path>" pointer of a worktree/submodule .git file.

// worktreeLayout builds a real-looking repo whose git dir is outside the
// checkout (like a worktree/submodule), with a loose commit and ref in it.
// It returns the checkout dir and the git dir.
func worktreeLayout(t *testing.T, wantTS int64) (checkout, gitDir string) {
	t.Helper()
	root := t.TempDir()
	checkout = filepath.Join(root, "checkout")
	gitDir = filepath.Join(root, "meta", "wt")
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(checkout, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sha := writeLooseCommit(t, gitDir, wantTS)
	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "main"), []byte(sha+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return checkout, gitDir
}

func TestGitLastCommitTime_WorktreeRelativeGitdir(t *testing.T) {
	t.Parallel()
	checkout, _ := worktreeLayout(t, 1720000000)
	// Relative to the directory holding the .git FILE, not to the process cwd.
	if err := os.WriteFile(filepath.Join(checkout, ".git"), []byte("gitdir: ../meta/wt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Start in a subdirectory: the walk-up must resolve against the .git file's dir.
	got, err := gitLastCommitTime(filepath.Join(checkout, "sub"))
	if err != nil {
		t.Fatalf("gitLastCommitTime: %v", err)
	}
	if got.Unix() != 1720000000 {
		t.Errorf("got unix %d, want 1720000000", got.Unix())
	}
}

func TestGitLastCommitTime_WorktreeAbsoluteGitdir(t *testing.T) {
	t.Parallel()
	checkout, gitDir := worktreeLayout(t, 1730000000)
	if err := os.WriteFile(filepath.Join(checkout, ".git"), []byte("gitdir: "+gitDir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := gitLastCommitTime(checkout)
	if err != nil {
		t.Fatalf("gitLastCommitTime: %v", err)
	}
	if got.Unix() != 1730000000 {
		t.Errorf("got unix %d, want 1730000000", got.Unix())
	}
}

func TestFindGitDir_RelativeGitdirResolvedAgainstGitFileDir(t *testing.T) {
	t.Parallel()
	checkout, gitDir := worktreeLayout(t, 1)
	if err := os.WriteFile(filepath.Join(checkout, ".git"), []byte("gitdir: ../meta/wt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := findGitDir(filepath.Join(checkout, "sub"))
	if err != nil {
		t.Fatalf("findGitDir: %v", err)
	}
	if got != gitDir {
		t.Errorf("findGitDir() = %q, want %q", got, gitDir)
	}
}

func TestFindGitDir_RejectsBadGitdirPointer(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	noHead := filepath.Join(root, "nohead")
	if err := os.MkdirAll(noHead, 0o755); err != nil {
		t.Fatal(err)
	}
	aFile := filepath.Join(root, "afile")
	if err := os.WriteFile(aFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"missing target":     "gitdir: " + filepath.Join(root, "nope") + "\n",
		"target is a file":   "gitdir: " + aFile + "\n",
		"dir without HEAD":   "gitdir: " + noHead + "\n",
		"empty path":         "gitdir: \n",
		"relative no target": "gitdir: ../../../../nowhere\n",
	}
	for name, content := range cases {
		checkout := filepath.Join(root, strings.ReplaceAll(name, " ", "_"))
		if err := os.MkdirAll(checkout, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(checkout, ".git"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := findGitDir(checkout)
		if err == nil {
			t.Errorf("%s: findGitDir accepted the pointer and returned %q", name, got)
			continue
		}
		if strings.Contains(err.Error(), "nowhere") || strings.Contains(err.Error(), "nope") {
			t.Errorf("%s: error quotes the pointer: %v", name, err)
		}
	}
}

// A gitdir pointer may be absolute (legit for worktrees/submodules) but the
// ref validation still bounds what is read from whatever it points to.
func TestGitLastCommitTime_GitdirPointerStillRefValidated(t *testing.T) {
	t.Parallel()
	checkout, gitDir := worktreeLayout(t, 1740000000)
	if err := os.WriteFile(filepath.Join(checkout, ".git"), []byte("gitdir: "+gitDir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: ../../../x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := gitLastCommitTime(checkout); err == nil {
		t.Error("hostile ref behind a gitdir pointer was followed")
	}
}

// Item 2: errors never quote attacker-controlled file content.

func TestGitLastCommitTime_JunkHEADNotQuoted(t *testing.T) {
	t.Parallel()
	junk := "LEAKED-" + strings.Repeat("J", 193) // 200 bytes, not hex, not a ref
	_, repo, _ := hostileRepo(t, junk+"\n")
	_, err := gitLastCommitTime(repo)
	if err == nil {
		t.Fatal("expected an error for a junk HEAD")
	}
	if strings.Contains(err.Error(), "LEAKED") || strings.Contains(err.Error(), "JJJJ") {
		t.Errorf("error quotes HEAD content: %v", err)
	}
	if !strings.Contains(err.Error(), "malformed HEAD/ref (200 bytes)") {
		t.Errorf("error = %q, want it to report only the byte count", err)
	}
}

func TestGitLastCommitTime_JunkRefFileNotQuoted(t *testing.T) {
	t.Parallel()
	_, repo, gitDir := hostileRepo(t, "ref: refs/heads/main\n")
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"long non-hex": "LEAKED-" + strings.Repeat("Z", 193),
		"too short":    "LEAK",
		"too long hex": strings.Repeat("a", 100),
	}
	for name, content := range cases {
		if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "main"), []byte(content+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := gitLastCommitTime(repo)
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		if strings.Contains(err.Error(), "LEAK") || strings.Contains(err.Error(), "ZZZZ") || strings.Contains(err.Error(), "aaaa") {
			t.Errorf("%s: error quotes ref file content: %v", name, err)
		}
	}
}

func TestResolvePackedRef_ErrorsDoNotQuote(t *testing.T) {
	t.Parallel()
	gitDir := t.TempDir()
	packed := "LEAKEDSHA refs/heads/bad\n" + strings.Repeat("a", 40) + " refs/heads/other\n"
	if err := os.WriteFile(filepath.Join(gitDir, "packed-refs"), []byte(packed), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"refs/heads/bad", "refs/heads/UNIQUE-MISSING-REF"} {
		_, err := resolvePackedRef(gitDir, ref)
		if err == nil {
			t.Fatalf("%s: expected an error", ref)
		}
		for _, leak := range []string{"LEAKEDSHA", "UNIQUE-MISSING-REF", "refs/heads/bad"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: error contains %q: %v", ref, leak, err)
			}
		}
	}
}
