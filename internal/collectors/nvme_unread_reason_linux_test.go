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
