//go:build linux

package collectors

import (
	"context"
	"reflect"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestParseSSHFileContent_FirstObtainedValueWins pins #1203 (DS1-F7).
// sshd_config(5): "Unless noted otherwise, for each keyword, the first
// obtained value will be used." The parser used to let later lines overwrite
// earlier ones, so a config sshd reads as "password auth allowed" was
// reported as hardened.
func TestParseSSHFileContent_FirstObtainedValueWins(t *testing.T) {
	t.Parallel()
	var info models.SecurityInfo
	parseSSHFileContent("PasswordAuthentication yes\nPasswordAuthentication no\nCiphers a\nCiphers b\n", &info)
	if !info.SSHPasswordAuth {
		t.Error("sshd applies the first PasswordAuthentication (yes); dsd reports password auth disabled")
	}
	if info.SSHCiphers != "a" {
		t.Errorf("SSHCiphers = %q, want the first value a", info.SSHCiphers)
	}
}

// TestParseSSHFileContent_AllowUsersAccumulates: AllowUsers is a documented
// exception, sshd keeps every directive.
func TestParseSSHFileContent_AllowUsersAccumulates(t *testing.T) {
	t.Parallel()
	var info models.SecurityInfo
	parseSSHFileContent("AllowUsers bob\nAllowUsers alice carol\n", &info)
	if want := []string{"bob", "alice", "carol"}; !reflect.DeepEqual(info.SSHAllowUsers, want) {
		t.Errorf("SSHAllowUsers = %v, want %v", info.SSHAllowUsers, want)
	}
}

// seedSSHFallback makes parseSSHConfig take the file-parse fallback (sshd -T
// absent) with the given files. Globs not listed in globs return no matches.
func seedSSHFallback(files map[string]string, globs map[string][]string) func(*source.Bundle) {
	return func(b *source.Bundle) {
		b.PutCmdNotFound("sshd", []string{"-T"})
		for _, p := range []string{"/etc/ssh/sshd_config.d/*.conf", "/etc/ssh/sshd_config.d/*.cfg"} {
			b.PutGlob(p, nil)
		}
		for p, m := range globs {
			b.PutGlob(p, m)
		}
		for p, c := range files {
			b.PutFile(p, []byte(c))
		}
	}
}

// TestParseSSHConfig_IncludeExpandedInPlace reproduces the layout checked
// against `sshd -T` on pve01 (OpenSSH, 2026-11-20): an Include at the top of
// sshd_config, 50-cloud-init.conf saying yes and 99-hardening.conf saying no.
// sshd -T printed "passwordauthentication yes", "x11forwarding yes",
// "ciphers aes256-ctr" and both AllowUsers entries (bob, then alice).
func TestParseSSHConfig_IncludeExpandedInPlace(t *testing.T) {
	const dropins = "/etc/ssh/sshd_config.d/*.conf"
	withFixtureSource(t, seedSSHFallback(map[string]string{
		"/etc/ssh/sshd_config":                      "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\nCiphers aes256-ctr\n",
		"/etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\nX11Forwarding yes\n",
		"/etc/ssh/sshd_config.d/60-extra.conf":      "AllowUsers bob\n",
		"/etc/ssh/sshd_config.d/99-hardening.conf":  "PasswordAuthentication no\nX11Forwarding no\nAllowUsers alice\n",
	}, map[string][]string{dropins: {
		"/etc/ssh/sshd_config.d/50-cloud-init.conf",
		"/etc/ssh/sshd_config.d/60-extra.conf",
		"/etc/ssh/sshd_config.d/99-hardening.conf",
	}}))
	info := &models.SecurityInfo{}
	parseSSHConfig(context.Background(), info)
	if !info.SSHPasswordAuth {
		t.Error("SSHPasswordAuth = false, want true (sshd -T: passwordauthentication yes)")
	}
	if !info.SSHX11Forwarding {
		t.Error("SSHX11Forwarding = false, want true (sshd -T: x11forwarding yes)")
	}
	if info.SSHCiphers != "aes256-ctr" {
		t.Errorf("SSHCiphers = %q, want aes256-ctr", info.SSHCiphers)
	}
	if want := []string{"bob", "alice"}; !reflect.DeepEqual(info.SSHAllowUsers, want) {
		t.Errorf("SSHAllowUsers = %v, want %v", info.SSHAllowUsers, want)
	}
	if info.SSHAuditSource != secTypeFile || info.SSHConfigUnreadable {
		t.Errorf("source=%q unreadable=%v, want file/false", info.SSHAuditSource, info.SSHConfigUnreadable)
	}
}

// TestParseSSHConfig_MatchInIncludeEndsWithFile: a Match block in an included
// file stops at the end of that file (sshd -T on pve01 applied the main
// file's PasswordAuthentication no after it).
func TestParseSSHConfig_MatchInIncludeEndsWithFile(t *testing.T) {
	withFixtureSource(t, seedSSHFallback(map[string]string{
		"/etc/ssh/sshd_config":             "Include sshd_config.d/*.conf\nPasswordAuthentication no\n",
		"/etc/ssh/sshd_config.d/10-m.conf": "Match User nobody\n  X11Forwarding yes\n",
	}, map[string][]string{"/etc/ssh/sshd_config.d/*.conf": {"/etc/ssh/sshd_config.d/10-m.conf"}}))
	info := &models.SecurityInfo{}
	parseSSHConfig(context.Background(), info)
	if info.SSHPasswordAuth {
		t.Error("SSHPasswordAuth = true, want false: the Match in the included file must not swallow the main file")
	}
	if info.SSHX11Forwarding {
		t.Error("SSHX11Forwarding = true, want false: a Match-scoped value is not the global policy")
	}
}

// TestParseSSHConfig_NoIncludeKeepsLegacyDropins: without an Include line the
// conventional drop-in dir is still read after the main file, and the main
// file's values come first.
func TestParseSSHConfig_NoIncludeKeepsLegacyDropins(t *testing.T) {
	withFixtureSource(t, seedSSHFallback(map[string]string{
		"/etc/ssh/sshd_config":             "PasswordAuthentication no\n",
		"/etc/ssh/sshd_config.d/50-x.conf": "PasswordAuthentication yes\nPermitRootLogin yes\n",
	}, map[string][]string{"/etc/ssh/sshd_config.d/*.conf": {"/etc/ssh/sshd_config.d/50-x.conf"}}))
	info := &models.SecurityInfo{}
	parseSSHConfig(context.Background(), info)
	if info.SSHPasswordAuth {
		t.Error("SSHPasswordAuth = true, want false (main file is read first)")
	}
	if !info.SSHRootLogin {
		t.Error("SSHRootLogin = false, want true from the drop-in")
	}
}

// TestParseSSHConfig_IncludeLoopTerminates: a self-including config must not
// recurse forever.
func TestParseSSHConfig_IncludeLoopTerminates(t *testing.T) {
	withFixtureSource(t, seedSSHFallback(map[string]string{
		"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config\nPasswordAuthentication no\n",
	}, map[string][]string{"/etc/ssh/sshd_config": {"/etc/ssh/sshd_config"}}))
	info := &models.SecurityInfo{}
	parseSSHConfig(context.Background(), info)
	if info.SSHPasswordAuth {
		t.Error("SSHPasswordAuth = true, want false")
	}
}
