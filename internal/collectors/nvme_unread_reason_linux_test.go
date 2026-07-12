//go:build linux

package collectors

import (
	"errors"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// absentToolSource makes both sbinToolPath branches miss: the lookpath/<tool>
// Cached probe errors (not on $PATH) and every Stat errors not-exist (not in the
// sbin dirs). So sbinToolPath("nvme") == "" — the binary is genuinely absent.
type absentToolSource struct {
	source.Source
}

func (absentToolSource) Cached(string, func() ([]byte, error)) ([]byte, error) {
	return nil, errors.New("not found in $PATH")
}

func (absentToolSource) Stat(string) (source.FileMeta, error) {
	return source.FileMeta{}, errors.New("no such file or directory")
}

// When nvme-cli is not installed anywhere, nvmeUnreadReason must report
// "tool_absent" — NOT "needs_root" — even on a non-root run, because sudo cannot
// conjure a missing binary. Regression guard for the arm64 Debian 13 EC2 bug
// (2026-06-25) where a non-root run wrongly told the operator to re-run as root
// while nvme-cli was simply not installed. euid-independent by construction:
// the absence check precedes the privilege check.
func TestNVMeUnreadReason_AbsentToolBeatsPrivilege(t *testing.T) {
	defer SetSource(SetSource(absentToolSource{}))

	if got := nvmeUnreadReason(); got != "tool_absent" {
		t.Errorf("nvme-cli genuinely absent must classify as tool_absent (correct remediation: install nvme-cli), got %q", got)
	}
}

// presentToolSource makes sbinToolPath("nvme") resolve to a real path via
// lookPath, so nvmeUnreadReason's decision falls through to the euid check.
type presentToolSource struct {
	source.Source
}

func (presentToolSource) Cached(string, func() ([]byte, error)) ([]byte, error) {
	return []byte("/usr/sbin/nvme"), nil
}

// TestNVMeUnreadReason_RootWithToolReportsError guards the final fallback: when
// nvme-cli IS installed and the caller IS root, a read failure is a genuine
// unexplained error — never mis-classified as tool_absent or needs_root. Forced
// deterministically via the geteuid seam (real test binaries aren't root, so
// os.Geteuid()==0 could never fire this in CI — that's why this branch was
// previously always skipped).
func TestNVMeUnreadReason_RootWithToolReportsError(t *testing.T) {
	swapGeteuid(t, 0)
	defer SetSource(SetSource(presentToolSource{}))

	if got := nvmeUnreadReason(); got != "error" {
		t.Errorf("nvme-cli present + root must classify as error (genuinely unexplained), got %q", got)
	}
}

// TestNVMeUnreadReason_NonRootWithToolNeedsRoot guards the middle branch: tool
// present but running unprivileged must ask for root, not report a bare
// "error" that gives the operator no remediation hint.
func TestNVMeUnreadReason_NonRootWithToolNeedsRoot(t *testing.T) {
	swapGeteuid(t, 1000)
	defer SetSource(SetSource(presentToolSource{}))

	if got := nvmeUnreadReason(); got != "needs_root" {
		t.Errorf("nvme-cli present + non-root must classify as needs_root, got %q", got)
	}
}
