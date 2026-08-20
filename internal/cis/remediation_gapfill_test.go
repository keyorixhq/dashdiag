package cis

// remediation_gapfill_test.go — closes coverage gaps found by a full
// coverage audit: iptablesPersistentRemoveCmd and unattendedUpgradesInstallCmd
// had no direct test of their own (unlike every sibling *InstallCmd/*RemoveCmd
// function in this file — see TestTimeSyncInstallCmd/TestAIDEInstallCmd for
// the established pattern this mirrors).

import (
	"strings"
	"testing"
)

func TestIptablesPersistentRemoveCmd(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pkgMgr  string
		wantSub string
	}{
		{"dnf", "not applicable"},
		{"yum", "not applicable"},
		{"tdnf", "not applicable"},
		{"zypper", "not applicable"},
		{"pacman", "not applicable"},
		{"apt", "apt purge iptables-persistent"},
		{"", "apt purge iptables-persistent"}, // unknown → Debian default
	}
	for _, c := range cases {
		got := iptablesPersistentRemoveCmd(c.pkgMgr)
		if !strings.Contains(got, c.wantSub) {
			t.Errorf("iptablesPersistentRemoveCmd(%q) = %q, want substring %q", c.pkgMgr, got, c.wantSub)
		}
	}
}

func TestUnattendedUpgradesInstallCmd(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pkgMgr  string
		wantSub string
	}{
		{"dnf", "dnf install dnf-automatic"},
		{"yum", "dnf install dnf-automatic"},
		{"tdnf", "dnf install dnf-automatic"},
		{"zypper", "zypper install zypper-needs-restarting"},
		{"apt", "apt install unattended-upgrades"},
		{"pacman", "apt install unattended-upgrades"}, // no pacman branch — falls to Debian default
		{"", "apt install unattended-upgrades"},       // unknown → Debian default
	}
	for _, c := range cases {
		got := unattendedUpgradesInstallCmd(c.pkgMgr)
		if !strings.Contains(got, c.wantSub) {
			t.Errorf("unattendedUpgradesInstallCmd(%q) = %q, want substring %q", c.pkgMgr, got, c.wantSub)
		}
	}
}
