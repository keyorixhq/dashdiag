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

// adaptRemediation must only touch FAILed auditd results — never a pass/skip, and
// never a non-auditd rule.
func TestAdaptRemediation_OnlyRewritesFailedAuditRules(t *testing.T) {
	pass := models.CISResult{ID: "4.1.1", Status: models.CISPass, Remediation: "keep"}
	if got := adaptRemediation(pass, "dnf"); got.Remediation != "keep" {
		t.Errorf("a passing 4.1.1 was rewritten: %q", got.Remediation)
	}
	other := models.CISResult{ID: "5.2.1", Status: models.CISFail, Remediation: "chmod 600 /etc/ssh/sshd_config"}
	if got := adaptRemediation(other, "dnf"); got.Remediation != "chmod 600 /etc/ssh/sshd_config" {
		t.Errorf("a non-auditd rule was rewritten: %q", got.Remediation)
	}
}
