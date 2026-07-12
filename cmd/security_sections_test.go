package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for the individual print*Section helpers in security.go
// that printSecurityReport dispatches to but whose branch coverage wasn't
// exercised by security_report_test.go's table of scenarios. No t.Parallel()
// (corrupts captureStdout's shared os.Stdout swap).

func TestSelinuxContextType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		context string
		want    string
	}{
		{"system_u:object_r:httpd_sys_content_t:s0", "httpd_sys_content_t"},
		{"too:short", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := selinuxContextType(c.context); got != c.want {
			t.Errorf("selinuxContextType(%q) = %q, want %q", c.context, got, c.want)
		}
	}
}

func TestPrintFailedLoginsSectionWithIPs(t *testing.T) {
	out := captureStdout(t, func() {
		printFailedLoginsSection(&models.SecurityInfo{FailedLogins: 12, FailedLoginIPs: []string{"1.2.3.4", "5.6.7.8"}})
	})
	if !strings.Contains(out, "12") {
		t.Errorf("should show the failed login count, got:\n%s", out)
	}
	if !strings.Contains(out, "1.2.3.4") || !strings.Contains(out, "5.6.7.8") {
		t.Errorf("should list each source IP, got:\n%s", out)
	}
}

func TestPrintMacOSSecuritySection(t *testing.T) {
	notDarwin := captureStdout(t, func() {
		printMacOSSecuritySection(&models.SecurityInfo{IsDarwin: false}, output.ModePlain)
	})
	if notDarwin != "" {
		t.Errorf("non-darwin host should print nothing, got:\n%s", notDarwin)
	}

	secure := captureStdout(t, func() {
		printMacOSSecuritySection(&models.SecurityInfo{
			IsDarwin: true, FileVaultEnabled: true, SIPEnabled: true, GatekeeperEnabled: true,
		}, output.ModePlain)
	})
	if !strings.Contains(secure, "disk encrypted") || !strings.Contains(secure, "enabled") {
		t.Errorf("a fully-secure macOS host should show all three as good, got:\n%s", secure)
	}

	insecure := captureStdout(t, func() {
		printMacOSSecuritySection(&models.SecurityInfo{
			IsDarwin: true, FileVaultEnabled: false, SIPEnabled: false, GatekeeperEnabled: false,
		}, output.ModePlain)
	})
	if !strings.Contains(insecure, "DISABLED") || !strings.Contains(insecure, "disk not encrypted") {
		t.Errorf("an insecure macOS host should flag SIP disabled and disk unencrypted, got:\n%s", insecure)
	}
}

func TestPrintRHELSecuritySection(t *testing.T) {
	absent := captureStdout(t, func() {
		printRHELSecuritySection(&models.SecurityInfo{AuditRules: -1}, output.ModePlain)
	})
	if absent != "" {
		t.Errorf("no RHEL security signals at all should print nothing, got:\n%s", absent)
	}

	fips := captureStdout(t, func() {
		printRHELSecuritySection(&models.SecurityInfo{FIPSEnabled: true, AuditRules: -1}, output.ModePlain)
	})
	if !strings.Contains(fips, "FIPS mode: enabled") {
		t.Errorf("FIPS enabled should say so, got:\n%s", fips)
	}

	legacy := captureStdout(t, func() {
		printRHELSecuritySection(&models.SecurityInfo{CryptoPolicy: "LEGACY", AuditRules: -1}, output.ModePlain)
	})
	if !strings.Contains(legacy, "FIPS mode: disabled") || !strings.Contains(legacy, "Crypto policy: LEGACY") {
		t.Errorf("a LEGACY crypto policy should warn, got:\n%s", legacy)
	}

	auditZero := captureStdout(t, func() {
		printRHELSecuritySection(&models.SecurityInfo{AuditRules: 0}, output.ModePlain)
	})
	if !strings.Contains(auditZero, "no rules configured") {
		t.Errorf("auditd running with 0 rules should warn, got:\n%s", auditZero)
	}

	auditRules := captureStdout(t, func() {
		printRHELSecuritySection(&models.SecurityInfo{AuditRules: 5}, output.ModePlain)
	})
	if !strings.Contains(auditRules, "5 rule(s) active") {
		t.Errorf("active audit rules should be counted, got:\n%s", auditRules)
	}

	usbguard := captureStdout(t, func() {
		printRHELSecuritySection(&models.SecurityInfo{USBGuardActive: true, AuditRules: -1}, output.ModePlain)
	})
	if !strings.Contains(usbguard, "USBGuard: active") {
		t.Errorf("active USBGuard should be shown, got:\n%s", usbguard)
	}

	aideNoDB := captureStdout(t, func() {
		printRHELSecuritySection(&models.SecurityInfo{AIDEInstalled: true, AIDEDBExists: false, AuditRules: -1}, output.ModePlain)
	})
	if !strings.Contains(aideNoDB, "database not initialised") {
		t.Errorf("AIDE installed without a database should warn, got:\n%s", aideNoDB)
	}

	aideStale := captureStdout(t, func() {
		printRHELSecuritySection(&models.SecurityInfo{AIDEInstalled: true, AIDEDBExists: true, AIDELastRunDays: 30, AuditRules: -1}, output.ModePlain)
	})
	if !strings.Contains(aideStale, "database 30 days old") {
		t.Errorf("a stale AIDE database should be flagged, got:\n%s", aideStale)
	}

	aideFresh := captureStdout(t, func() {
		printRHELSecuritySection(&models.SecurityInfo{AIDEInstalled: true, AIDEDBExists: true, AIDELastRunDays: 1, AuditRules: -1}, output.ModePlain)
	})
	if !strings.Contains(aideFresh, "database 1 days old") {
		t.Errorf("a fresh AIDE database should be reported OK, got:\n%s", aideFresh)
	}
}

func TestPrintSUSESecuritySection(t *testing.T) {
	absent := captureStdout(t, func() { printSUSESecuritySection(&models.SecurityInfo{}, output.ModePlain) })
	if absent != "" {
		t.Errorf("no SUSE signals should print nothing, got:\n%s", absent)
	}

	neverRun := captureStdout(t, func() {
		printSUSESecuritySection(&models.SecurityInfo{SupportconfigAvailable: true, SupportconfigLastRunDays: -1}, output.ModePlain)
	})
	if !strings.Contains(neverRun, "never run") {
		t.Errorf("a never-run supportconfig should say so, got:\n%s", neverRun)
	}

	stale := captureStdout(t, func() {
		printSUSESecuritySection(&models.SecurityInfo{SupportconfigAvailable: true, SupportconfigLastRunDays: 45}, output.ModePlain)
	})
	if !strings.Contains(stale, "last run 45 days ago") {
		t.Errorf("a stale supportconfig should warn, got:\n%s", stale)
	}

	fresh := captureStdout(t, func() {
		printSUSESecuritySection(&models.SecurityInfo{SupportconfigAvailable: true, SupportconfigLastRunDays: 2, SupportconfigArchive: "/var/log/scc_x.txz"}, output.ModePlain)
	})
	if !strings.Contains(fresh, "scc_x.txz") {
		t.Errorf("a fresh supportconfig should name the archive, got:\n%s", fresh)
	}

	expired := captureStdout(t, func() {
		printSUSESecuritySection(&models.SecurityInfo{SUSEConnectRegistered: true, SUSEConnectExpiresDays: 0, SUSEConnectStatus: "EXPIRED"}, output.ModePlain)
	})
	if !strings.Contains(expired, "EXPIRED") {
		t.Errorf("an expired subscription should say EXPIRED, got:\n%s", expired)
	}

	renewNow := captureStdout(t, func() {
		printSUSESecuritySection(&models.SecurityInfo{SUSEConnectRegistered: true, SUSEConnectExpiresDays: 5}, output.ModePlain)
	})
	if !strings.Contains(renewNow, "renew immediately") {
		t.Errorf("a subscription expiring within 14 days should say renew immediately, got:\n%s", renewNow)
	}

	renewSoon := captureStdout(t, func() {
		printSUSESecuritySection(&models.SecurityInfo{SUSEConnectRegistered: true, SUSEConnectExpiresDays: 20}, output.ModePlain)
	})
	if !strings.Contains(renewSoon, "renew soon") {
		t.Errorf("a subscription expiring within 15-30 days should say renew soon, got:\n%s", renewSoon)
	}

	activeSub := captureStdout(t, func() {
		printSUSESecuritySection(&models.SecurityInfo{SUSEConnectRegistered: true, SUSEConnectExpiresDays: 90, SUSEConnectStatus: "ACTIVE"}, output.ModePlain)
	})
	if !strings.Contains(activeSub, "active") {
		t.Errorf("a healthy subscription should say active, got:\n%s", activeSub)
	}

	unknownExpiry := captureStdout(t, func() {
		printSUSESecuritySection(&models.SecurityInfo{SUSEConnectRegistered: true, SUSEConnectExpiresDays: -1}, output.ModePlain)
	})
	if !strings.Contains(unknownExpiry, "expiry unknown") {
		t.Errorf("a negative-but-not-recognised expiry should say expiry unknown, got:\n%s", unknownExpiry)
	}
}

func TestPrintSnapperSection(t *testing.T) {
	nilSnap := captureStdout(t, func() { printSnapperSection(nil, output.ModePlain) })
	if nilSnap != "" {
		t.Errorf("nil snapper info should print nothing, got:\n%s", nilSnap)
	}

	notAvailable := captureStdout(t, func() { printSnapperSection(&models.SnapperInfo{Available: false}, output.ModePlain) })
	if notAvailable != "" {
		t.Errorf("unavailable snapper should print nothing, got:\n%s", notAvailable)
	}

	none := captureStdout(t, func() {
		printSnapperSection(&models.SnapperInfo{Available: true, SnapshotCount: 0}, output.ModePlain)
	})
	if !strings.Contains(none, "no snapshots found") {
		t.Errorf("zero snapshots should warn, got:\n%s", none)
	}

	stale := captureStdout(t, func() {
		printSnapperSection(&models.SnapperInfo{Available: true, SnapshotCount: 3, LastSnapshotH: -1, TotalSpaceGB: 1.5}, output.ModePlain)
	})
	if !strings.Contains(stale, "no recent snapshot") || !strings.Contains(stale, "1.50 GiB") {
		t.Errorf("no recent snapshot should warn and show space, got:\n%s", stale)
	}

	recent := captureStdout(t, func() {
		printSnapperSection(&models.SnapperInfo{Available: true, SnapshotCount: 3, LastSnapshotH: 0}, output.ModePlain)
	})
	if !strings.Contains(recent, "< 1h ago") {
		t.Errorf("a snapshot within the last hour should say so, got:\n%s", recent)
	}

	older := captureStdout(t, func() {
		printSnapperSection(&models.SnapperInfo{Available: true, SnapshotCount: 3, LastSnapshotH: 5}, output.ModePlain)
	})
	if !strings.Contains(older, "5h ago") {
		t.Errorf("an older snapshot should show hours ago, got:\n%s", older)
	}
}
