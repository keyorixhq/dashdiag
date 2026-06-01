package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestNixosFixHint(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		want     string
		wantDrop bool
	}{
		// Bug 1 — sysctl persistence
		{
			"sysctl swappiness",
			"to persist: echo 'vm.swappiness=10' >> /etc/sysctl.d/99-dsd.conf",
			`to persist (NixOS): boot.kernel.sysctl = { "vm.swappiness" = 10; }; in configuration.nix, then nixos-rebuild switch`,
			false,
		},
		{
			"sysctl max_map_count",
			"to persist: echo 'vm.max_map_count=262144' >> /etc/sysctl.d/99-dsd.conf",
			`to persist (NixOS): boot.kernel.sysctl = { "vm.max_map_count" = 262144; }; in configuration.nix, then nixos-rebuild switch`,
			false,
		},
		{
			"sysctl dotted net key",
			"to persist: echo 'net.core.somaxconn=4096' >> /etc/sysctl.d/99-dsd.conf",
			`to persist (NixOS): boot.kernel.sysctl = { "net.core.somaxconn" = 4096; }; in configuration.nix, then nixos-rebuild switch`,
			false,
		},
		// Bug 2 — sshd_config
		{
			"sshd PermitRootLogin",
			"to fix: set PermitRootLogin no in /etc/ssh/sshd_config",
			`to fix (NixOS): services.openssh.settings.PermitRootLogin = "no"; in configuration.nix, then nixos-rebuild switch`,
			false,
		},
		{
			"sshd MaxAuthTries with numeric value",
			"to fix: set MaxAuthTries 4 in /etc/ssh/sshd_config",
			`to fix (NixOS): services.openssh.settings.MaxAuthTries = "4"; in configuration.nix, then nixos-rebuild switch`,
			false,
		},
		{
			"sshd Ciphers list",
			"to fix: set Ciphers aes256-gcm@openssh.com,aes128-ctr in /etc/ssh/sshd_config",
			`to fix (NixOS): services.openssh.settings.Ciphers = "aes256-gcm@openssh.com,aes128-ctr"; in configuration.nix, then nixos-rebuild switch`,
			false,
		},
		{
			"sshd restart dropped",
			"to fix: systemctl restart sshd",
			"",
			true,
		},
		{
			"checkAuth combined echo+restart",
			"to fix:     echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && systemctl restart sshd",
			`to fix (NixOS): services.openssh.settings.PermitRootLogin = "no"; in configuration.nix, then nixos-rebuild switch`,
			false,
		},
		{
			"sshd Protocol removal",
			"to fix: remove or comment out 'Protocol' line in /etc/ssh/sshd_config",
			"to fix (NixOS): remove any 'Protocol' line from services.openssh.extraConfig, then nixos-rebuild switch",
			false,
		},
		// Bug 3 — rsyslog
		{
			"rsyslog install",
			"to fix: apt install rsyslog  OR  dnf install rsyslog  OR  zypper install rsyslog",
			"to fix (NixOS): services.rsyslogd.enable = true; in configuration.nix, then nixos-rebuild switch",
			false,
		},
		// Passthrough — must not be touched
		{
			"inspect line untouched",
			"to inspect: grep PermitRootLogin /etc/ssh/sshd_config",
			"to inspect: grep PermitRootLogin /etc/ssh/sshd_config",
			false,
		},
		{
			"runtime sysctl -w untouched",
			"to fix: sysctl -w vm.swappiness=10",
			"to fix: sysctl -w vm.swappiness=10",
			false,
		},
		{
			"note line untouched",
			"note: CBC-mode ciphers are vulnerable to BEAST/Lucky13",
			"note: CBC-mode ciphers are vulnerable to BEAST/Lucky13",
			false,
		},
		{
			"verify line untouched",
			"to verify: sshd -T | grep ciphers",
			"to verify: sshd -T | grep ciphers",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, drop := nixosFixHint(tt.in)
			if drop != tt.wantDrop {
				t.Fatalf("drop = %v, want %v", drop, tt.wantDrop)
			}
			if !drop && got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

// TestNixosifyHints verifies the whole-insight pass: rewrites matching hints,
// drops the standalone restart, and preserves notes/order.
func TestNixosifyHints(t *testing.T) {
	in := []models.Insight{
		{
			Level: "CRIT", Check: "Hardening", Message: "SSH permits root login",
			Hints: []string{
				"to fix: set PermitRootLogin no in /etc/ssh/sshd_config",
				"to fix: systemctl restart sshd",
			},
		},
		{
			Level: "INFO", Check: "Logs", Message: "no text log fallback",
			Hints: []string{
				"to fix: apt install rsyslog  OR  dnf install rsyslog  OR  zypper install rsyslog",
				"note:   standard Unix tools cannot read binary journal files",
			},
		},
	}
	out := nixosifyHints(in)

	wantSSH := []string{
		`to fix (NixOS): services.openssh.settings.PermitRootLogin = "no"; in configuration.nix, then nixos-rebuild switch`,
	}
	if len(out[0].Hints) != 1 || out[0].Hints[0] != wantSSH[0] {
		t.Errorf("ssh hints = %#v, want %#v", out[0].Hints, wantSSH)
	}
	if len(out[1].Hints) != 2 ||
		out[1].Hints[0] != "to fix (NixOS): services.rsyslogd.enable = true; in configuration.nix, then nixos-rebuild switch" ||
		out[1].Hints[1] != "note:   standard Unix tools cannot read binary journal files" {
		t.Errorf("logs hints = %#v", out[1].Hints)
	}
}
