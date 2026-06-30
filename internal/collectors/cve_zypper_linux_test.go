//go:build linux

package collectors

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// `zypper lp` / `list-patches` EXIT NON-ZERO when patches are applicable
// (ZYPPER_EXIT_INF_*_UPDATE_NEEDED) and write the patch table to stdout. The CVE
// collectors used plain runCmd, which DISCARDS stdout on a non-zero exit — so a
// system WITH pending security patches read as "scan failed" / CVEUnknown instead of
// VULNERABLE (a missed-CVE under-report). These guard the runCmdOutput/runCmdCombined
// fixes plus the zypp-lock handling (the BUG-088 class, surfaced by the #662 tripwire).

// a security patch table zypper emits ALONGSIDE a non-zero "patches needed" exit.
const zypperLPNonZeroTable = "Repository | Patch | Category | Severity | Interactive | Status | Summary\n" +
	"repo-sec | openssl-fix | security | important | --- | needed | fixes CVE-2024-1234"

func TestCheckCVEZypperKeepsTableOnNonZeroExit(t *testing.T) {
	fake := fakeRunSource{run: func(_ string, _ []string) source.Result {
		return source.Result{Stdout: []byte(zypperLPNonZeroTable), ExitCode: 100}
	}}
	defer SetSource(SetSource(fake))

	res := checkCVEZypper(context.Background(), "CVE-2024-1234")
	if res.Status != models.CVEVulnerable {
		t.Fatalf("non-zero exit WITH a needed security patch must read CVEVulnerable, got %s "+
			"(runCmd would have dropped the table → false CVEUnknown)", res.Status)
	}
}

func TestCheckCVEZypperLockedExitIsUnknownNotPatched(t *testing.T) {
	// exit 7 (ZYPP_LOCKED) with empty stdout must NOT read as patched/not-affected.
	fake := fakeRunSource{run: func(_ string, _ []string) source.Result {
		return source.Result{Stderr: []byte("System management is locked by the application with pid 1 (zypper)."), ExitCode: 7}
	}}
	defer SetSource(SetSource(fake))

	res := checkCVEZypper(context.Background(), "CVE-2024-1234")
	if res.Status != models.CVEUnknown {
		t.Fatalf("a locked/empty zypper lp must read CVEUnknown, got %s", res.Status)
	}
}

func TestScanAllZypperKeepsTableOnNonZeroExit(t *testing.T) {
	// 8-col list-patches table emitted with a non-zero "patches needed" exit.
	table := "Repository | Patch Name | Category | Severity | Interactive | Status | Since | Summary\n" +
		"SLE-Module | SUSE-2024-1234 | security | critical | --- | needed | 2024-01-01 | fix for CVE-2024-1234"
	fake := fakeRunSource{run: func(_ string, _ []string) source.Result {
		return source.Result{Stdout: []byte(table), ExitCode: 100}
	}}
	defer SetSource(SetSource(fake))

	res := scanAllZypper(context.Background())
	if res.ScanFailed {
		t.Fatalf("a non-zero exit WITH a security patch table must parse, not ScanFailed (runCmd dropped it before)")
	}
	if len(res.Critical) != 1 {
		t.Fatalf("expected 1 critical advisory parsed from the table, got %d", len(res.Critical))
	}
}

func TestScanAllZypperLockedExitIsScanFailedNotEmpty(t *testing.T) {
	// exit 7 with the lock message on stderr (folded into combined output): must be
	// ScanFailed with a 'locked' reason, NEVER a false "no pending security patches".
	// A cancelled ctx makes the lock-retry break immediately (no real 4s sleep).
	fake := fakeRunSource{run: func(_ string, _ []string) source.Result {
		return source.Result{Stderr: []byte("System management is locked by the application with pid 1 (zypper)."), ExitCode: 7}
	}}
	defer SetSource(SetSource(fake))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := scanAllZypper(ctx)
	if !res.ScanFailed {
		t.Fatal("a held zypp lock must read ScanFailed, never a clean 'no CVEs'")
	}
	if !strings.Contains(res.StatusReason, "locked") {
		t.Fatalf("ScanFailed reason should name the lock, got %q", res.StatusReason)
	}
}
