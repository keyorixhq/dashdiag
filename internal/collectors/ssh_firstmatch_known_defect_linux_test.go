//go:build linux

package collectors

import (
	"os"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestParseSSHFileContent_FirstObtainedValueWins pins DS1-F7 (CANDIDATE,
// found by reading the code while auditing the first-match/last-match class
// of DS1-F2/F3). sshd_config(5): "Unless noted otherwise, for each keyword,
// the first obtained value will be used." parseSSHFileContent lets every
// later line overwrite the earlier one, and the non-root fallback in
// parseSSHConfig parses sshd_config and then each drop-in in glob order with
// the same overwrite rule. The classic cloud-image layout therefore reads as
// hardened when it is not: 50-cloud-init.conf says "PasswordAuthentication
// yes", a later 99-hardening.conf says "no", sshd applies yes (first
// obtained), dsd reports no.
//
// Only the file-parse fallback is affected (non-root runs where `sshd -T` is
// refused); `sshd -T` prints each key once. Skipped unless
// DSD_KNOWN_DEFECTS=1. Not confirmed against a live sshd in this session (no
// openssh-server image offline); the expectation rests on sshd_config(5).
//
// What it does NOT verify: keywords that are documented exceptions to
// first-match (none of the parsed ones are), Include placement inside the
// main file, or Match-block handling.
func TestParseSSHFileContent_FirstObtainedValueWins(t *testing.T) {
	if os.Getenv("DSD_KNOWN_DEFECTS") != "1" {
		t.Skip("DS1-F7 known defect candidate; set DSD_KNOWN_DEFECTS=1 to run")
	}
	t.Run("duplicate in one file", func(t *testing.T) {
		var info models.SecurityInfo
		parseSSHFileContent("PasswordAuthentication yes\nPasswordAuthentication no\n", &info)
		if !info.SSHPasswordAuth {
			t.Error("sshd applies the first PasswordAuthentication (yes); dsd reports password auth disabled")
		}
	})
	t.Run("drop-ins in glob order", func(t *testing.T) {
		var info models.SecurityInfo
		// The same sequence parseSSHConfig's fallback performs for
		// /etc/ssh/sshd_config.d/50-cloud-init.conf then 99-hardening.conf.
		parseSSHFileContent("PasswordAuthentication yes\nPermitRootLogin yes\n", &info)
		parseSSHFileContent("PasswordAuthentication no\nPermitRootLogin no\n", &info)
		if !info.SSHPasswordAuth || !info.SSHRootLogin {
			t.Errorf("sshd applies the first drop-in (yes/yes); dsd reports PasswordAuth=%v RootLogin=%v", info.SSHPasswordAuth, info.SSHRootLogin)
		}
	})
}
