package init_pkg

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestContainsAny(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		list    []string
		targets []string
		want    bool
	}{
		{"exact match", []string{"nginx", "sshd"}, []string{"nginx"}, true},
		{"case insensitive", []string{"NGINX"}, []string{"nginx"}, true},
		{"no match", []string{"sshd", "cron"}, []string{"nginx", "apache2"}, false},
		{"empty list", nil, []string{"nginx"}, false},
		{"empty targets", []string{"nginx"}, nil, false},
		{"match among many targets", []string{"redis-server"}, []string{"postgres", "mysqld", "redis-server", "mongod"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := containsAny(c.list, c.targets...); got != c.want {
				t.Errorf("containsAny(%v, %v) = %v, want %v", c.list, c.targets, got, c.want)
			}
		})
	}
}

func TestClassifyProfile(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		procs []string
		want  string
	}{
		{"nginx present", []string{"bash", "nginx", "sshd"}, "web"},
		{"apache2 present", []string{"apache2"}, "web"},
		{"postgres present", []string{"postgres", "bash"}, "database"},
		{"redis present", []string{"redis-server"}, "database"},
		{"kubelet present", []string{"kubelet", "containerd"}, "kubernetes"},
		{"proxmox present", []string{"pvedaemon"}, "proxmox"},
		{"nothing recognized", []string{"bash", "sshd", "cron"}, "general"},
		{"empty process list", nil, "general"},
		{"web takes priority over database when both present", []string{"nginx", "postgres"}, "web"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := classifyProfile(c.procs); got != c.want {
				t.Errorf("classifyProfile(%v) = %q, want %q", c.procs, got, c.want)
			}
		})
	}
}

// DetectServerProfile hits the real OS process list — smoke test only, per the
// project's own testdata/fixtures rule for anything reading real /proc or ps.
func TestDetectServerProfile_Smoke(t *testing.T) {
	t.Parallel()
	valid := map[string]bool{"web": true, "database": true, "kubernetes": true, "proxmox": true, "general": true}
	got, ok := DetectServerProfile()
	if !valid[got] {
		t.Errorf("DetectServerProfile() = %q, want one of the known profile names", got)
	}
	if !ok {
		t.Error("DetectServerProfile() ok = false, want true — the real process list should be readable in this test environment")
	}
}

// darwinProcessNames shells out to the real "ps aux" and parses its output.
// It isn't gated on runtime.GOOS internally, so it's exercised directly here
// as a smoke test (real "ps" is available on this Linux CI/dev box too, and
// BSD-style "ps aux" column layout — COMMAND as the 11th field — matches).
func TestDarwinProcessNames_Smoke(t *testing.T) {
	t.Parallel()
	names, ok := darwinProcessNames()
	if !ok {
		t.Fatal("darwinProcessNames() ok = false, want true — `ps aux` should succeed in this test environment")
	}
	if len(names) == 0 {
		t.Skip("no process names parsed from `ps aux` in this environment")
	}
	for _, n := range names {
		if n == "" {
			t.Errorf("darwinProcessNames() returned an empty name among %v", names)
		}
	}
}

// With newPSCmd pointed at a nonexistent binary, darwinProcessNames() takes
// its error branch and returns (nil, false) — exercises that path without
// needing a real macOS host. Swaps newPSCmd rather than $PATH: since
// internal-init-01-04, "ps" resolves via source.ResolveTrustedTool, which
// deliberately ignores $PATH (see its doc comment), so clearing $PATH no
// longer has any effect on which binary this runs. Not t.Parallel(): the var
// swap is only race-free because Go's test runner finishes all serial tests
// before starting the parallel batch (same constraint as the drilldown
// package's swapRunCmd tests).
func TestDarwinProcessNames_PsNotFound(t *testing.T) {
	old := newPSCmd
	newPSCmd = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, filepath.Join(t.TempDir(), "definitely-not-a-real-binary"), "aux")
	}
	defer func() { newPSCmd = old }()

	names, ok := darwinProcessNames()
	if names != nil {
		t.Errorf("darwinProcessNames() names = %v, want nil when `ps` cannot be found/run", names)
	}
	if ok {
		t.Error("darwinProcessNames() ok = true, want false — the scan itself failed, must not read as a genuine empty result")
	}
}

// TestDarwinProcessNamesBoundsHungPs covers subprocess-wrappers-07: a bare
// exec.Command("ps", "aux") has no deadline at all, so a wedged `ps` (a stuck
// kernel table lock, a pathological process count) would hang
// darwinProcessNames — and therefore `dsd init` — forever. Swap newPSCmd to a
// fake "ps" that sleeps far longer than psTimeout and confirm the call
// returns promptly instead of blocking for the sleep's full duration.
//
// Swaps newPSCmd rather than $PATH (see TestDarwinProcessNames_PsNotFound's
// comment for why $PATH no longer reaches a substitute binary here).
func TestDarwinProcessNamesBoundsHungPs(t *testing.T) {
	dir := t.TempDir()
	fakePS := filepath.Join(dir, "ps")
	// Use /bin/sleep by absolute path, not a bare "sleep" — the script would
	// otherwise need $PATH to resolve it, and this fixture deliberately does
	// NOT rely on $PATH (see above). `exec` replaces the shell with sleep in
	// the same process rather than forking a child, so killing the "ps"
	// process actually kills the sleep — a forked (non-exec'd) grandchild
	// would keep the output pipe open after the shell itself dies, masking a
	// working cancellation as a hang.
	script := "#!/bin/sh\nexec /bin/sleep 5\n"
	if err := os.WriteFile(fakePS, []byte(script), 0o755); err != nil { //nolint:gosec // test fixture, needs +x
		t.Fatalf("writing fake ps: %v", err)
	}

	oldNewPSCmd := newPSCmd
	newPSCmd = func(ctx context.Context) *exec.Cmd {
		cmd := exec.CommandContext(ctx, fakePS, "aux")
		cmd.WaitDelay = 100 * time.Millisecond // matches source.ExecWaitDelay
		return cmd
	}
	defer func() { newPSCmd = oldNewPSCmd }()
	oldTimeout := psTimeout
	psTimeout = 300 * time.Millisecond
	defer func() { psTimeout = oldTimeout }()

	start := time.Now()
	names, ok := darwinProcessNames()
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("darwinProcessNames() took %s — a hung `ps` was not bounded by psTimeout (blocked instead of being killed)", elapsed)
	}
	if names != nil {
		t.Errorf("darwinProcessNames() = %v, want nil when ps is killed for exceeding its deadline", names)
	}
	if ok {
		t.Error("darwinProcessNames() ok = true, want false — a killed/timed-out ps is a scan failure, not a genuine empty result")
	}
}

// runningProcessNames dispatches on runtime.GOOS. This smoke test just
// confirms it returns without panicking on whichever branch the current
// build/OS takes; the darwin-only branch (runtime.GOOS != "linux") is not
// reachable on this Linux test host and is recorded as a known gap.
func TestRunningProcessNames_Smoke(t *testing.T) {
	t.Parallel()
	_, _ = runningProcessNames()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("unexpected GOOS for this smoke test")
	}
}

func TestLinuxProcessNamesFrom(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Pid directory with a comm file.
	pid1 := filepath.Join(dir, "1")
	if err := os.Mkdir(pid1, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid1, "comm"), []byte("systemd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Pid directory without a comm file — silently skipped.
	pid2 := filepath.Join(dir, "2")
	if err := os.Mkdir(pid2, 0o755); err != nil {
		t.Fatal(err)
	}
	// Non-directory entry — skipped by the IsDir guard.
	if err := os.WriteFile(filepath.Join(dir, "version"), []byte("Linux\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, ok := linuxProcessNamesFrom(dir)
	if len(got) != 1 || got[0] != "systemd" {
		t.Errorf("linuxProcessNamesFrom() = %v, want [systemd]", got)
	}
	if !ok {
		t.Error("linuxProcessNamesFrom() ok = false, want true — the directory was readable")
	}
}

// TestLinuxProcessNamesFrom_MissingDir is the regression test for the
// false-OK fix: a ReadDir failure (missing/unreadable /proc) must return
// ok=false, distinguishing it from a genuinely process-free directory —
// both previously returned the identical nil slice with no way to tell them
// apart, which left classifyProfile(nil) silently defaulting to "general"
// on a scan failure the same way it does on a real daemon-free host.
func TestLinuxProcessNamesFrom_MissingDir(t *testing.T) {
	t.Parallel()
	got, ok := linuxProcessNamesFrom("/nonexistent/proc-dir")
	if got != nil {
		t.Errorf("linuxProcessNamesFrom() = %v, want nil for missing dir", got)
	}
	if ok {
		t.Error("linuxProcessNamesFrom() ok = true, want false when the directory can't be read")
	}
}
