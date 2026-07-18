package cis

import (
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestRulesHaveNoHardcodedDistroHints is the regression guard for the Oracle
// Linux 9 finding (#649): rule 4.1.2's remediation hardcoded the Debian auditd
// sample-rules path (/usr/share/doc/auditd/examples/stig.rules), which does not
// exist on RHEL/SUSE/Arch. `dsd cis` renders CISResult.Remediation directly and
// does NOT pass it through analysis.AdaptHostHints (the adapter that distroifies
// `apt install` for dsd health's insights), so any package-manager command or
// distro-specific path hardcoded in a rule leaks verbatim on the wrong distro.
//
// New package-install / sample-rule hints must therefore be produced through a
// helper in remediation.go (auditInstallCmd/auditRulesCmd/…), which switches on
// the host package manager — never inlined in rules.go.
func TestRulesHaveNoHardcodedDistroHints(t *testing.T) {
	src, err := os.ReadFile("rules.go")
	if err != nil {
		t.Fatalf("read rules.go: %v", err)
	}
	text := string(src)

	// Literal tokens that are only correct on one distro family. A bare manager
	// name ("apt") is fine (it appears as a switch argument); the install-command
	// and absolute sample-rule paths are what leak.
	forbidden := []string{
		"apt install", "apt-get", "dnf install", "yum install",
		"zypper install", "zypper in ", "pacman -S", "apk add", "emerge ",
		"/usr/share/doc/auditd", "/usr/share/audit/sample-rules",
	}
	for _, tok := range forbidden {
		if strings.Contains(text, tok) {
			t.Errorf("rules.go hardcodes a distro-specific remediation token %q — "+
				"`dsd cis` does not run hints through analysis.AdaptHostHints, so this "+
				"leaks on other distros. Move it into a package-manager switch in "+
				"remediation.go instead.", tok)
		}
	}
}

// TestAuditRemediation_AllPackageManagers exercises the remediation helpers
// directly across every supported family, so each install command and sample-rule
// path is asserted in one place.
func TestAuditRemediation_AllPackageManagers(t *testing.T) {
	cases := []struct {
		pkgMgr      string
		wantInstall string // substring the install command must contain
		wantPath    string // sample-rules path the rules command must contain
	}{
		{"dnf", "dnf install audit", "/usr/share/audit/sample-rules/"},
		{"yum", "dnf install audit", "/usr/share/audit/sample-rules/"},
		{"tdnf", "dnf install audit", "/usr/share/audit/sample-rules/"},
		{"zypper", "zypper install audit", "/usr/share/audit/sample-rules/"},
		{"pacman", "pacman -S audit", "/usr/share/audit/sample-rules/"},
		{"apt", "apt install auditd", "/usr/share/doc/auditd/examples/"},
		{"", "apt install auditd", "/usr/share/doc/auditd/examples/"}, // unknown → Debian default
	}
	for _, c := range cases {
		if got := auditInstallCmd(c.pkgMgr); !strings.Contains(got, c.wantInstall) {
			t.Errorf("auditInstallCmd(%q) = %q, want substring %q", c.pkgMgr, got, c.wantInstall)
		}
		if got := auditRulesCmd(c.pkgMgr); !strings.Contains(got, c.wantPath) {
			t.Errorf("auditRulesCmd(%q) = %q, want substring %q", c.pkgMgr, got, c.wantPath)
		}
	}
}

// adaptRemediation must only touch FAILed auditd/timesync results — never a
// pass/skip, and never an unrecognised rule.
func TestAdaptRemediation_OnlyRewritesFailedAuditRules(t *testing.T) {
	pass := models.CISResult{ID: "4.1.1", Status: models.CISPass, Remediation: "keep"}
	if got := adaptRemediation(pass, "dnf"); got.Remediation != "keep" {
		t.Errorf("a passing 4.1.1 was rewritten: %q", got.Remediation)
	}
	other := models.CISResult{ID: "5.2.1", Status: models.CISFail, Remediation: "chmod 600 /etc/ssh/sshd_config"}
	if got := adaptRemediation(other, "dnf"); got.Remediation != "chmod 600 /etc/ssh/sshd_config" {
		t.Errorf("a non-install rule was rewritten: %q", got.Remediation)
	}
}

// TestTimeSyncInstallCmd exercises timeSyncInstallCmd across all supported
// package-manager families.
func TestTimeSyncInstallCmd(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pkgMgr  string
		wantSub string
	}{
		{"dnf", "dnf install chrony"},
		{"yum", "dnf install chrony"},
		{"tdnf", "dnf install chrony"},
		{"zypper", "zypper install chrony"},
		{"pacman", "pacman -S chrony"},
		{"apt", "apt install chrony"},
		{"", "apt install chrony"}, // unknown → Debian default
	}
	for _, c := range cases {
		if got := timeSyncInstallCmd(c.pkgMgr); !strings.Contains(got, c.wantSub) {
			t.Errorf("timeSyncInstallCmd(%q) = %q, want substring %q", c.pkgMgr, got, c.wantSub)
		}
	}
}

// TestAdaptRemediation_2_1_1 verifies that rule 2.1.1 FAILs get their
// remediation rewritten per package manager, while non-FAIL results are untouched.
func TestAdaptRemediation_2_1_1(t *testing.T) {
	t.Parallel()
	failing := models.CISResult{ID: "2.1.1", Status: models.CISFail, Remediation: "install a time sync daemon"}
	if got := adaptRemediation(failing, "dnf"); !strings.Contains(got.Remediation, "dnf install chrony") {
		t.Errorf("2.1.1 FAIL with dnf: got %q, want 'dnf install chrony'", got.Remediation)
	}
	if got := adaptRemediation(failing, "apt"); !strings.Contains(got.Remediation, "apt install chrony") {
		t.Errorf("2.1.1 FAIL with apt: got %q, want 'apt install chrony'", got.Remediation)
	}
	passing := models.CISResult{ID: "2.1.1", Status: models.CISPass, Remediation: "keep"}
	if got := adaptRemediation(passing, "dnf"); got.Remediation != "keep" {
		t.Errorf("2.1.1 PASS was rewritten: %q", got.Remediation)
	}
}

// TestAIDEInstallCmd verifies every package manager gets a distinct, valid install command.
func TestAIDEInstallCmd(t *testing.T) {
	cases := []struct {
		pkgMgr string
		want   string // required substring
	}{
		{"dnf", "dnf install aide"},
		{"yum", "dnf install aide"},
		{"tdnf", "dnf install aide"},
		{"zypper", "zypper install aide"},
		{"pacman", "pacman -S aide"},
		{"apt", "apt install aide"},
		{"", "apt install aide"}, // unknown → Debian default
	}
	for _, c := range cases {
		if got := aideInstallCmd(c.pkgMgr); !strings.Contains(got, c.want) {
			t.Errorf("aideInstallCmd(%q) = %q, want substring %q", c.pkgMgr, got, c.want)
		}
	}
}

// TestAdaptRemediation_1_3_1 checks that a failed 1.3.1 result is rewritten per package manager.
func TestAdaptRemediation_1_3_1(t *testing.T) {
	fail := models.CISResult{ID: "1.3.1", Status: models.CISFail, Remediation: "apt install aide"}
	if got := adaptRemediation(fail, "dnf"); !strings.Contains(got.Remediation, "dnf install") {
		t.Errorf("1.3.1 dnf: remediation not rewritten: %q", got.Remediation)
	}
	pass := models.CISResult{ID: "1.3.1", Status: models.CISPass, Remediation: "keep"}
	if got := adaptRemediation(pass, "dnf"); got.Remediation != "keep" {
		t.Errorf("passing 1.3.1 was rewritten: %q", got.Remediation)
	}
}
