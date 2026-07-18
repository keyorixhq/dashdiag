package cis

import "github.com/keyorixhq/dashdiag/internal/models"

// This file is the ONLY place in the cis package allowed to hold distro-specific
// package-manager commands or absolute sample-rule paths. `dsd cis` renders
// CISResult.Remediation directly and does NOT route it through
// analysis.AdaptHostHints (the adapter that rewrites `apt install` → `dnf`/`zypper`
// for dsd health's insights), so a hardcoded apt-ism in a rule would leak verbatim
// on RHEL/SUSE/Arch. TestRulesHaveNoHardcodedDistroHints enforces that rules.go
// carries no such literal — new package-install hints must come through here.

// aideInstallCmd returns the package-manager-appropriate command to install AIDE
// (Advanced Intrusion Detection Environment). CIS 1.3.1 requires AIDE; the install
// command differs by distro: the package is "aide" on Debian/Ubuntu, "aide" on
// RHEL/SUSE, but requires initialization after install.
func aideInstallCmd(pkgMgr string) string {
	switch pkgMgr {
	case "dnf", "yum", "tdnf":
		return "dnf install aide && aide --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
	case "zypper":
		return "zypper install aide && aide --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
	case "pacman":
		return "pacman -S aide && aide --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
	default: // apt and unknown
		return "apt install aide && aide --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
	}
}

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

// apparmorInstallCmd returns the package-manager-appropriate command to install
// AppArmor and its utilities (rule 1.6.1, CIS Ubuntu-specific).
func apparmorInstallCmd(pkgMgr string) string {
	switch pkgMgr {
	case "dnf", "yum", "tdnf":
		return "dnf install apparmor apparmor-utils && systemctl enable --now apparmor"
	case "zypper":
		return "zypper install apparmor-parser apparmor-utils && systemctl enable --now apparmor"
	case "pacman":
		return "pacman -S apparmor && systemctl enable --now apparmor"
	default: // apt
		return "apt install apparmor apparmor-utils && systemctl enable --now apparmor"
	}
}

// macInstallCmd returns the package-manager-appropriate command to install a MAC
// framework. RHEL/Rocky/Fedora use SELinux; Debian/Ubuntu/SLES/Arch use AppArmor.
func macInstallCmd(pkgMgr string) string {
	switch pkgMgr {
	case "dnf", "yum", "tdnf":
		return "dnf install selinux-policy-targeted && reboot"
	case "zypper":
		return "zypper install apparmor-parser && systemctl enable --now apparmor"
	case "pacman":
		return "pacman -S apparmor && systemctl enable --now apparmor"
	default: // apt and unknown
		return "apt install apparmor && systemctl enable --now apparmor"
	}
}

// sudoInstallCmd returns the package-manager-appropriate command to install sudo.
func sudoInstallCmd(pkgMgr string) string {
	switch pkgMgr {
	case "dnf", "yum", "tdnf":
		return "dnf install sudo"
	case "zypper":
		return "zypper install sudo"
	case "pacman":
		return "pacman -S sudo"
	default: // apt and unknown
		return "apt install sudo"
	}
}

// rsyslogInstallCmd returns the package-manager-appropriate command to install rsyslog.
func rsyslogInstallCmd(pkgMgr string) string {
	switch pkgMgr {
	case "dnf", "yum", "tdnf":
		return "dnf install rsyslog && systemctl enable --now rsyslog"
	case "zypper":
		return "zypper install rsyslog && systemctl enable --now rsyslog"
	case "pacman":
		return "pacman -S rsyslog && systemctl enable --now rsyslog"
	default: // apt and unknown
		return "apt install rsyslog && systemctl enable --now rsyslog"
	}
}

// firewallInstallCmd returns the package-manager-appropriate command to install and
// enable a firewall. Debian/Ubuntu default to ufw; RHEL/SLES/Arch to firewalld.
func firewallInstallCmd(pkgMgr string) string {
	switch pkgMgr {
	case "dnf", "yum", "tdnf":
		return "dnf install firewalld && systemctl enable --now firewalld"
	case "zypper":
		return "zypper install firewalld && systemctl enable --now firewalld"
	case "pacman":
		return "pacman -S firewalld && systemctl enable --now firewalld"
	default: // apt and unknown
		return "apt install ufw && ufw enable"
	}
}

// adaptRemediation rewrites a result's remediation for the host's package manager.
// Most CIS remediations are package-manager-agnostic; rules that install packages
// or reference distro-specific paths are the exception — their commands differ by
// family and must be produced here rather than hardcoded in rules.go.
func adaptRemediation(res models.CISResult, pkgMgr string) models.CISResult {
	if res.Status != models.CISFail {
		return res
	}
	switch res.ID {
	case "1.3.1":
		res.Remediation = aideInstallCmd(pkgMgr)
	case "2.1.1":
		res.Remediation = timeSyncInstallCmd(pkgMgr)
	case "3.3.1":
		res.Remediation = macInstallCmd(pkgMgr)
	case "3.5.1":
		// Only rewrite the "no tooling" path; the "tooling present but inactive"
		// path uses generic enable commands that need no package-manager switch.
		if res.Finding == "no firewall tooling detected" {
			res.Remediation = firewallInstallCmd(pkgMgr)
		}
	case "4.1.1":
		res.Remediation = auditInstallCmd(pkgMgr)
	case "4.1.2":
		res.Remediation = auditRulesCmd(pkgMgr)
	case "5.3.1":
		res.Remediation = sudoInstallCmd(pkgMgr)
	case "4.2.1":
		res.Remediation = rsyslogInstallCmd(pkgMgr)
	case "1.6.1":
		res.Remediation = apparmorInstallCmd(pkgMgr)
	}
	return res
}
