//go:build linux

package collectors

import "testing"

// Characterization tests for the pure CVE-classification helpers in cve_linux.go:
// the apt package-name heuristic severity, the arch-audit severity mapping, and
// the distro -> OVAL key mapping. These drive the CVE health scan's WARN/CRIT
// bucketing, so their behavior must be pinned.

func TestAptPackageSeverity(t *testing.T) {
	tests := []struct {
		pkg  string
		want string
	}{
		// arch/version suffixes are stripped before matching
		{"libssl3t64:amd64", "CRITICAL"},
		{"libssl3=3.0.13", "CRITICAL"},
		// CRITICAL bucket
		{"linux-image-6.1.0", "CRITICAL"},
		{"libc6", "CRITICAL"},
		{"sudo", "CRITICAL"},
		{"openssh-server", "CRITICAL"},
		// IMPORTANT bucket
		{"curl", "IMPORTANT"},
		{"docker-ce", "IMPORTANT"},
		{"nginx-common", "IMPORTANT"},
		{"python3.11", "IMPORTANT"},
		// MODERATE bucket
		{"libpng16-16", "MODERATE"},
		{"vim-tiny", "MODERATE"},
		{"libglib2.0-0", "MODERATE"},
		// LOW (no match)
		{"cowsay", "LOW"},
		{"fortune-mod", "LOW"},
	}
	for _, tt := range tests {
		if got := aptPackageSeverity(tt.pkg); got != tt.want {
			t.Errorf("aptPackageSeverity(%q) = %q, want %q", tt.pkg, got, tt.want)
		}
	}
}

func TestArchAuditSeverity(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"Critical", "critical"},
		{"HIGH", "important"},
		{"medium", "moderate"},
		{"Low", "low"},
		{"  unknown-label ", "low"}, // default + trim/case
		{"", "low"},
	}
	for _, tt := range tests {
		if got := archAuditSeverity(tt.in); got != tt.want {
			t.Errorf("archAuditSeverity(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDistroKeyFor(t *testing.T) {
	tests := []struct {
		distro string
		want   string
	}{
		{"SLES", "sles:16"},
		{"opensuse-tumbleweed", "opensuse-tumbleweed"},
		{"rhel", "rhel:10"},
		{"Fedora", "fedora:44"},
		{"ubuntu", "ubuntu"}, // default lower-cases and passes through
		{"Debian", "debian"},
	}
	for _, tt := range tests {
		if got := distroKeyFor(tt.distro); got != tt.want {
			t.Errorf("distroKeyFor(%q) = %q, want %q", tt.distro, got, tt.want)
		}
	}
}
