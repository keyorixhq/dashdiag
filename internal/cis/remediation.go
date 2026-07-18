package cis

import "github.com/keyorixhq/dashdiag/internal/models"

// This file is the ONLY place in the cis package allowed to hold distro-specific
// package-manager commands or absolute sample-rule paths. `dsd cis` renders
// CISResult.Remediation directly and does NOT route it through
// analysis.AdaptHostHints (the adapter that rewrites `apt install` → `dnf`/`zypper`
// for dsd health's insights), so a hardcoded apt-ism in a rule would leak verbatim
// on RHEL/SUSE/Arch. TestRulesHaveNoHardcodedDistroHints enforces that rules.go
// carries no such literal — new package-install hints must come through here.

// auditInstallCmd returns the package-manager-appropriate command to install the
// audit daemon. The CIS rule set is authored Ubuntu-first, but `dsd cis` runs on
// any distro — an apt command is wrong (and absent) on RHEL/SUSE/Arch hosts.
func auditInstallCmd(pkgMgr string) string {
	switch pkgMgr {
	case "dnf", "yum", "tdnf":
		return "dnf install audit && systemctl enable --now auditd"
	case "zypper":
		return "zypper install audit && systemctl enable --now auditd"
	case "pacman":
		return "pacman -S audit && systemctl enable --now auditd"
	default: // apt and unknown
		return "apt install auditd && systemctl enable --now auditd"
	}
}

// auditRulesCmd returns the command to seed audit rules from the distro's shipped
// sample rules. The sample-rules path differs by family: Debian/Ubuntu ship them
// under /usr/share/doc/auditd/examples, RHEL/SUSE under /usr/share/audit/sample-rules
// (verified on Oracle Linux 9 / the audit package). A Debian path on a RHEL host
// points at a file that does not exist.
func auditRulesCmd(pkgMgr string) string {
	switch pkgMgr {
	case "dnf", "yum", "tdnf", "zypper", "pacman":
		return "install rules: cp /usr/share/audit/sample-rules/30-stig.rules /etc/audit/rules.d/ && augenrules --load"
	default: // apt and unknown
		return "install rules: cp /usr/share/doc/auditd/examples/stig.rules /etc/audit/rules.d/ && augenrules --load"
	}
}

// timeSyncInstallCmd returns the package-manager-appropriate command to install chrony.
// The service name differs by family: Debian/Ubuntu use "chrony"; RHEL/SUSE use "chronyd".
func timeSyncInstallCmd(pkgMgr string) string {
	switch pkgMgr {
	case "dnf", "yum", "tdnf":
		return "dnf install chrony && systemctl enable --now chronyd"
	case "zypper":
		return "zypper install chrony && systemctl enable --now chronyd"
	case "pacman":
		return "pacman -S chrony && systemctl enable --now chronyd"
	default: // apt and unknown
		return "apt install chrony && systemctl enable --now chrony"
	}
}

// adaptRemediation rewrites a result's remediation for the host's package manager.
// Most CIS remediations are package-manager-agnostic; install-type rules (2.1.1,
// 4.1.1/4.1.2) are the exception — their commands differ by package manager.
func adaptRemediation(res models.CISResult, pkgMgr string) models.CISResult {
	if res.Status != models.CISFail {
		return res
	}
	switch res.ID {
	case "2.1.1":
		res.Remediation = timeSyncInstallCmd(pkgMgr)
	case "4.1.1":
		res.Remediation = auditInstallCmd(pkgMgr)
	case "4.1.2":
		res.Remediation = auditRulesCmd(pkgMgr)
	}
	return res
}
