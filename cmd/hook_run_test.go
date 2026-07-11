package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// withHookStdin redirects os.Stdin to a pipe fed with content and restores it
// on cleanup — mirrors internal/tui/select_test.go's withStdin helper (that
// one is unexported in its own package, so it can't be reused directly here).
// Feeding stdin this way also guarantees tui.IsTTY() reads false (a pipe is
// never a char device), so runHookInstall always takes the scripted
// multiSelectText path regardless of the outer test environment's terminal.
func withHookStdin(t *testing.T, content string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })
	go func() {
		_, _ = w.WriteString(content)
		_ = w.Close()
	}()
}

// newBareHookCmd builds a bare cobra.Command with the flags runHookInstall
// reads via cmd.Flags().GetBool.
func newBareHookCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("dry-run", false, "")
	f.Bool("plain", false, "")
	return c
}

// TestRunHookInstallNoSelection exercises the empty-selection path: an EOF (or
// blank) on stdin yields no chosen hooks, and the command must say so and
// return without touching the filesystem.
func TestRunHookInstallNoSelection(t *testing.T) {
	withHookStdin(t, "\n")
	c := newBareHookCmd()
	out := captureStdout(t, func() {
		if err := runHookInstall(c, nil); err != nil {
			t.Fatalf("runHookInstall with no selection: %v", err)
		}
	})
	if !strings.Contains(out, "No hooks selected") {
		t.Errorf("an empty selection should say so, got:\n%s", out)
	}
}

// TestRunHookInstallDryRunAll exercises every install* function's dry-run
// branch plus printHookCommands, none of which touch the filesystem.
func TestRunHookInstallDryRunAll(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	withHookStdin(t, "1,2,3,4,5,6\n")
	c := newBareHookCmd()
	_ = c.Flags().Set("dry-run", "true")
	out := captureStdout(t, func() {
		if err := runHookInstall(c, nil); err != nil {
			t.Fatalf("runHookInstall --dry-run (all options): %v", err)
		}
	})
	if !strings.Contains(out, "DRY RUN") {
		t.Errorf("dry-run mode should announce itself, got:\n%s", out)
	}
	for _, want := range []string{
		"Would modify", "Would create", "Hook commands",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output should mention %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Hooks installed") {
		t.Errorf("dry-run must not claim hooks were installed, got:\n%s", out)
	}
}

// TestRunHookInstallRealWrites exercises the non-dry-run install paths that
// write relative to the working directory (pre-deploy script, git pre-push
// hook, GitHub Actions workflow) plus the SSH shell-RC append, all confined
// to a temp HOME/cwd. The systemd-timer option is deliberately excluded here
// (it always targets /etc/systemd/system — see TestRunHookInstallSystemdTimerNoRoot).
func TestRunHookInstallRealWrites(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o750); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	// Select: SSH login, Pre-deploy, Git pre-push, GitHub Actions (skip systemd).
	withHookStdin(t, "1,2,3,5\n")
	c := newBareHookCmd()
	out := captureStdout(t, func() {
		if err := runHookInstall(c, nil); err != nil {
			t.Fatalf("runHookInstall: %v", err)
		}
	})
	if !strings.Contains(out, "Hooks installed") {
		t.Errorf("a non-empty, non-dry-run selection should confirm installation, got:\n%s", out)
	}

	if _, err := os.Stat(filepath.Join(dir, "scripts", "check-health.sh")); err != nil {
		t.Errorf("pre-deploy script should have been written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git", "hooks", "pre-push")); err != nil {
		t.Errorf("git pre-push hook should have been written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".github", "workflows", "dsd-health.yml")); err != nil {
		t.Errorf("GitHub Actions workflow should have been written: %v", err)
	}
	rc := shellRCPath()
	data, err := os.ReadFile(rc) // #nosec G304 -- test-owned temp HOME path
	if err != nil {
		t.Fatalf("reading shell RC %s: %v", rc, err)
	}
	if !strings.Contains(string(data), "dsd health") {
		t.Errorf("SSH snippet should have been appended to %s, got:\n%s", rc, data)
	}
}

// TestRunHookInstallGitHookNoRepo exercises installGitHook's "not a git
// repository" error branch.
func TestRunHookInstallGitHookNoRepo(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	withHookStdin(t, "3\n") // Git pre-push hook only
	c := newBareHookCmd()
	errOut := captureStderr(t, func() {
		if err := runHookInstall(c, nil); err != nil {
			t.Fatalf("runHookInstall: %v", err)
		}
	})
	if !strings.Contains(errOut, "not a git repository") {
		t.Errorf("installing the git hook outside a repo should error on stderr, got:\n%s", errOut)
	}
}

// TestShellRCPathZshrc guards the .zshrc-preferred branch: when both could
// exist, .zshrc wins.
func TestShellRCPathZshrc(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte(""), 0o600); err != nil {
		t.Fatalf("WriteFile .zshrc: %v", err)
	}
	if got, want := shellRCPath(), filepath.Join(home, ".zshrc"); got != want {
		t.Errorf("shellRCPath() = %q, want %q when .zshrc exists", got, want)
	}
}

// TestShellRCPathBashrcFallback guards the .bashrc fallback when no .zshrc exists.
func TestShellRCPathBashrcFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if got, want := shellRCPath(), filepath.Join(home, ".bashrc"); got != want {
		t.Errorf("shellRCPath() = %q, want %q when no .zshrc exists", got, want)
	}
}

// TestInstallSSHHookOpenError exercises installSSHHook's write-error branch:
// the target path exists but is a directory, so os.OpenFile must fail
// gracefully (error to stderr), not panic.
func TestInstallSSHHookOpenError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.Mkdir(filepath.Join(home, ".bashrc"), 0o750); err != nil {
		t.Fatalf("mkdir .bashrc: %v", err)
	}
	errOut := captureStderr(t, func() { installSSHHook(false) })
	if !strings.Contains(errOut, "could not write") {
		t.Errorf("a directory in place of .bashrc should produce a write error, got:\n%s", errOut)
	}
}

// TestInstallPreDeployMkdirError exercises installPreDeploy's MkdirAll-error
// branch: a plain file named "scripts" blocks directory creation.
func TestInstallPreDeployMkdirError(t *testing.T) {
	dir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })
	if err := os.WriteFile(filepath.Join(dir, "scripts"), []byte(""), 0o600); err != nil {
		t.Fatalf("WriteFile scripts (as a file): %v", err)
	}
	errOut := captureStderr(t, func() { installPreDeploy(false) })
	if errOut == "" {
		t.Error("a blocked scripts/ directory should produce an error on stderr")
	}
}

// TestInstallGitHubActionsMkdirError exercises installGitHubActions'
// MkdirAll-error branch: a plain file named ".github" blocks directory
// creation.
func TestInstallGitHubActionsMkdirError(t *testing.T) {
	dir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })
	if err := os.WriteFile(filepath.Join(dir, ".github"), []byte(""), 0o600); err != nil {
		t.Fatalf("WriteFile .github (as a file): %v", err)
	}
	errOut := captureStderr(t, func() { installGitHubActions(false) })
	if errOut == "" {
		t.Error("a blocked .github/ directory should produce an error on stderr")
	}
}

// TestInstallGitHookMkdirError exercises installGitHook's MkdirAll-error
// branch: ".git" exists but is a plain file, so ".git/hooks" can't be created
// under it, and os.Stat(".git") alone doesn't distinguish that from a real repo.
func TestInstallGitHookMkdirError(t *testing.T) {
	dir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })
	if err := os.WriteFile(filepath.Join(dir, ".git"), []byte(""), 0o600); err != nil {
		t.Fatalf("WriteFile .git (as a file): %v", err)
	}
	errOut := captureStderr(t, func() { installGitHook(false) })
	if strings.Contains(errOut, "not a git repository") {
		t.Errorf("a .git file (not dir) passes the existence check — the mkdir failure should surface instead, got:\n%s", errOut)
	}
	if errOut == "" {
		t.Error("a blocked .git/hooks directory should produce an error on stderr")
	}
}

// TestInstallGitHookWriteError exercises installGitHook's WriteFile-error
// branch: .git/hooks exists and MkdirAll succeeds, but the target path is
// itself a directory, so writing the hook file fails.
func TestInstallGitHookWriteError(t *testing.T) {
	dir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })
	if err := os.MkdirAll(filepath.Join(dir, ".git", "hooks", "pre-push"), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	errOut := captureStderr(t, func() { installGitHook(false) })
	if errOut == "" {
		t.Error("a pre-push path that's a directory should produce a write error on stderr")
	}
}

// TestRunHookInstallSystemdTimerNoRoot exercises installSystemdTimer's
// permission-error branch — writing to /etc/systemd/system as a non-root test
// process must fail gracefully (error to stderr), never succeed or panic.
func TestRunHookInstallSystemdTimerNoRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — the permission-denied path can't be exercised")
	}
	t.Setenv("HOME", t.TempDir())
	withHookStdin(t, "4\n") // systemd timer only
	c := newBareHookCmd()
	errOut := captureStderr(t, func() {
		if err := runHookInstall(c, nil); err != nil {
			t.Fatalf("runHookInstall: %v", err)
		}
	})
	if !strings.Contains(errOut, "may need sudo") {
		t.Errorf("a permission-denied systemd write should hint at sudo, got:\n%s", errOut)
	}
}
