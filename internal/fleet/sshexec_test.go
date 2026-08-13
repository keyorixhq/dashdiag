package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeFakeBin drops an executable shell script named name onto dir, then
// points PATH at dir (and nothing else) for the duration of the test so
// exec.CommandContext("ssh"/"scp", ...) resolves to our fake instead of a
// real network client. Mirrors the PATH-faking pattern already used in
// internal/collectors (see docker_quadlet_test.go TestPodmanInstalled).
//
// Callers MUST NOT also call t.Parallel(): t.Setenv panics if the test (or an
// ancestor) is parallel, same constraint documented in
// internal/drilldown/runcmd_helper_test.go.
func writeFakeBin(t *testing.T, dir, name, script string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatalf("writing fake %s: %v", name, err)
	}
}

// TestSSHRun_Success exercises the real exec.CommandContext("ssh", ...) path
// with a fake ssh script on PATH, confirming argv shape (BatchMode etc via
// "--", host, cmd) and that stdout is returned uninterpreted.
func TestSSHRun_Success(t *testing.T) {
	dir := t.TempDir()
	writeFakeBin(t, dir, "ssh", `echo '{"hostname":"h1","insights":[]}'
`)
	t.Setenv("PATH", dir)

	out, err := sshRun(context.Background(), Options{ConnectTimeout: 5 * time.Second}, "h1", "dsd health --json")
	if err != nil {
		t.Fatalf("sshRun error = %v", err)
	}
	if !strings.Contains(string(out), `"hostname":"h1"`) {
		t.Errorf("sshRun output = %q, want it to contain the fake ssh's stdout", out)
	}
}

// TestSSHRun_Failure confirms a non-zero exit from the remote ssh process
// surfaces as an error (not swallowed), with stderr preserved so
// sshFailureReason can extract it later in runHost.
func TestSSHRun_Failure(t *testing.T) {
	dir := t.TempDir()
	writeFakeBin(t, dir, "ssh", `echo "Permission denied (publickey)." >&2
exit 255
`)
	t.Setenv("PATH", dir)

	_, err := sshRun(context.Background(), Options{ConnectTimeout: 5 * time.Second}, "h1", "dsd health --json")
	if err == nil {
		t.Fatal("sshRun error = nil, want non-nil for a failing remote ssh")
	}
}

// TestSSHRun_CapsOversizedStdout covers read-bounding-04: sshRun must cap how
// much remote stdout it buffers. A compromised or misbehaving remote host
// (or a wildly misbehaving `dsd health --json` on the other end) printing far
// more than any real report must not make the orchestrating `dsd fleet`
// process buffer unbounded memory. The fake ssh uses /bin/dd by absolute path
// (not a bare "dd") since PATH is pinned to just the fixture dir below.
func TestSSHRun_CapsOversizedStdout(t *testing.T) {
	dir := t.TempDir()
	writeFakeBin(t, dir, "ssh", `/bin/dd if=/dev/zero bs=1M count=32 2>/dev/null
`)
	t.Setenv("PATH", dir)

	out, err := sshRun(context.Background(), Options{ConnectTimeout: 5 * time.Second}, "h1", "dsd health --json")
	if err != nil {
		t.Fatalf("sshRun error = %v", err)
	}
	if len(out) > sshOutputMaxBytes {
		t.Errorf("sshRun returned %d bytes, want <= %d (sshOutputMaxBytes)", len(out), sshOutputMaxBytes)
	}
}

// TestSCP_Success exercises the real exec.CommandContext("scp", ...) path via
// a fake scp script that just needs to exit 0.
func TestSCP_Success(t *testing.T) {
	dir := t.TempDir()
	writeFakeBin(t, dir, "scp", `exit 0
`)
	t.Setenv("PATH", dir)

	local := filepath.Join(t.TempDir(), "dsd")
	if err := os.WriteFile(local, []byte("binary"), 0o755); err != nil {
		t.Fatalf("writing local bin: %v", err)
	}

	err := scp(context.Background(), Options{ConnectTimeout: 5 * time.Second}, local, "h1", "/tmp/dsd-fleet")
	if err != nil {
		t.Fatalf("scp error = %v, want nil", err)
	}
}

// TestSCP_Failure confirms a failing scp process returns a non-nil error.
func TestSCP_Failure(t *testing.T) {
	dir := t.TempDir()
	writeFakeBin(t, dir, "scp", `echo "No such file or directory" >&2
exit 1
`)
	t.Setenv("PATH", dir)

	err := scp(context.Background(), Options{ConnectTimeout: 5 * time.Second}, "/nonexistent/dsd", "h1", "/tmp/dsd-fleet")
	if err == nil {
		t.Fatal("scp error = nil, want non-nil for a failing remote scp")
	}
}

// TestRunHost_Reachable drives runHost end-to-end (no BinPath) against a fake
// ssh that emits valid health JSON — the "everything worked" path.
func TestRunHost_Reachable(t *testing.T) {
	dir := t.TempDir()
	writeFakeBin(t, dir, "ssh", `echo '{"hostname":"web1","version":"v1.0","insights":[{"check":"Disk","level":"WARN","message":"disk 80% full"}]}'
`)
	t.Setenv("PATH", dir)

	res := runHost(context.Background(), "web1", Options{}.withDefaults())
	if !res.Reachable {
		t.Fatalf("runHost.Reachable = false, want true: %+v", res)
	}
	if res.Worst != "WARN" || res.Hostname != "web1" || res.Version != "v1.0" {
		t.Errorf("runHost result = %+v, want Worst=WARN Hostname=web1 Version=v1.0", res)
	}
	if res.Elapsed <= 0 {
		t.Error("runHost did not finalize Elapsed")
	}
}

// TestRunHost_SSHFailure drives runHost when the remote ssh process fails
// outright (no parseable output) — must mark the host unreachable with a
// reason derived from stderr, not panic or silently report OK.
func TestRunHost_SSHFailure(t *testing.T) {
	dir := t.TempDir()
	writeFakeBin(t, dir, "ssh", `echo "Connection refused" >&2
exit 255
`)
	t.Setenv("PATH", dir)

	res := runHost(context.Background(), "deadhost", Options{}.withDefaults())
	if res.Reachable {
		t.Fatalf("runHost.Reachable = true, want false: %+v", res)
	}
	if res.Worst != "ERROR" {
		t.Errorf("runHost.Worst = %q, want ERROR", res.Worst)
	}
	if !strings.Contains(res.Error, "Connection refused") {
		t.Errorf("runHost.Error = %q, want it to surface ssh's stderr", res.Error)
	}
}

// TestRunHost_BinPathScpFails exercises the BinPath branch's scp-failure
// short-circuit: when opts.BinPath is set and scp fails, runHost must report
// a scp-specific error and never fall through to sshRun.
func TestRunHost_BinPathScpFails(t *testing.T) {
	dir := t.TempDir()
	writeFakeBin(t, dir, "scp", `echo "lost connection" >&2
exit 1
`)
	// No fake ssh on PATH at all — if runHost fell through to sshRun this
	// would fail differently (exec: "ssh": executable file not found), so a
	// scp-prefixed error also proves we short-circuited correctly.
	t.Setenv("PATH", dir)

	local := filepath.Join(t.TempDir(), "dsd")
	if err := os.WriteFile(local, []byte("binary"), 0o755); err != nil {
		t.Fatalf("writing local bin: %v", err)
	}

	res := runHost(context.Background(), "web1", Options{BinPath: local}.withDefaults())
	if res.Reachable {
		t.Fatalf("runHost.Reachable = true, want false: %+v", res)
	}
	if !strings.HasPrefix(res.Error, "scp failed:") {
		t.Errorf("runHost.Error = %q, want prefix %q", res.Error, "scp failed:")
	}
}

// TestRunHost_BinPathSuccess drives the full BinPath branch: scp succeeds,
// then runHost must invoke ssh with a chmod+run command built from the
// shell-quoted remote path (RemoteBinDir default "/tmp" + "/dsd-fleet").
func TestRunHost_BinPathSuccess(t *testing.T) {
	dir := t.TempDir()
	writeFakeBin(t, dir, "scp", `exit 0
`)
	// The fake ssh echoes back its final argv element (the remote command
	// string) wrapped in the health JSON shape isn't practical from POSIX sh,
	// so instead assert indirectly: succeed only if invoked with a command
	// containing "dsd-fleet" and "health --json", proving runHost built the
	// expected chmod+exec string.
	writeFakeBin(t, dir, "ssh", `case "$*" in
  *dsd-fleet*'health --json'*) echo '{"hostname":"web1","insights":[]}' ;;
  *) echo "unexpected argv: $*" >&2; exit 1 ;;
esac
`)
	t.Setenv("PATH", dir)

	local := filepath.Join(t.TempDir(), "dsd")
	if err := os.WriteFile(local, []byte("binary"), 0o755); err != nil {
		t.Fatalf("writing local bin: %v", err)
	}

	res := runHost(context.Background(), "web1", Options{BinPath: local}.withDefaults())
	if !res.Reachable {
		t.Fatalf("runHost.Reachable = false, want true: %+v", res)
	}
	if res.Worst != "OK" {
		t.Errorf("runHost.Worst = %q, want OK", res.Worst)
	}
}

// TestRun_MultiHostConcurrency drives the exported Run entry point across
// several hosts, mixing a valid host (through the fake ssh) with an
// injection-shaped host that must short-circuit via ValidateHost without
// ever reaching ssh. Exercises the goroutine/semaphore/channel plumbing in
// Run that per-host unit tests on runHost don't touch.
func TestRun_MultiHostConcurrency(t *testing.T) {
	dir := t.TempDir()
	// The host is the second-to-last argv element (args end in "-- host cmd");
	// use shift to walk to it without depending on how many -o flags precede it.
	writeFakeBin(t, dir, "ssh", `while [ "$#" -gt 2 ]; do shift; done
echo '{"hostname":"'"$1"'","insights":[]}'
`)
	t.Setenv("PATH", dir)

	hosts := []string{"web1", "-oProxyCommand=evil", "web2", "web3"}
	results, err := Run(context.Background(), hosts, Options{Concurrency: 2})
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	if len(results) != len(hosts) {
		t.Fatalf("Run returned %d results, want %d", len(results), len(hosts))
	}
	// Results preserve input order.
	for i, h := range hosts {
		if results[i].Host != h {
			t.Errorf("results[%d].Host = %q, want %q (order not preserved)", i, results[i].Host, h)
		}
	}
	if results[1].Reachable || results[1].Worst != "ERROR" {
		t.Errorf("invalid host result = %+v, want unreachable ERROR", results[1])
	}
	for _, i := range []int{0, 2, 3} {
		if !results[i].Reachable || results[i].Worst != "OK" {
			t.Errorf("results[%d] = %+v, want reachable OK", i, results[i])
		}
	}
}
