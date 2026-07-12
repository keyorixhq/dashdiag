package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for printSELinuxSection/printAppArmorSection branches
// not exercised by security_report_test.go's scenario table: SELinux
// booleans, AVC groups (both fix kinds, plus the >5 cap), port labels, file
// context issues, and AppArmor denial groups vs bare denial counts. No
// t.Parallel() (corrupts captureStdout's shared os.Stdout swap).

func TestPrintSELinuxSectionAVCGroupsBooleanFix(t *testing.T) {
	info := &models.SecurityInfo{
		SELinuxMode: "enforcing",
		SELinuxAVCGroups: []models.SELinuxAVCGroup{
			{Scontext: "httpd_t", Tcontext: "container_t", Tclass: "file", Perms: []string{"read", "write"}, Count: 12, BooleanFix: "httpd_can_network_connect"},
		},
	}
	out := captureStdout(t, func() { printSELinuxSection(info, output.ModePlain) })
	if !strings.Contains(out, "httpd_t") || !strings.Contains(out, "×12") {
		t.Errorf("an AVC group should show its source context and count, got:\n%s", out)
	}
	if !strings.Contains(out, "setsebool -P httpd_can_network_connect on") {
		t.Errorf("a boolean-fixable AVC group should show the setsebool fix, got:\n%s", out)
	}
}

func TestPrintSELinuxSectionAVCGroupsFixCmd(t *testing.T) {
	info := &models.SecurityInfo{
		SELinuxMode: "enforcing",
		SELinuxAVCGroups: []models.SELinuxAVCGroup{
			{Scontext: "sshd_t", Tcontext: "user_home_t", Tclass: "dir", Perms: []string{"search"}, Count: 3, FixCmd: "restorecon -Rv /home/user"},
		},
	}
	out := captureStdout(t, func() { printSELinuxSection(info, output.ModePlain) })
	if !strings.Contains(out, "restorecon -Rv /home/user") {
		t.Errorf("a non-boolean AVC group should show its FixCmd, got:\n%s", out)
	}
}

// TestPrintSELinuxSectionAVCGroupsCapped guards the ">5 groups" truncation.
func TestPrintSELinuxSectionAVCGroupsCapped(t *testing.T) {
	groups := make([]models.SELinuxAVCGroup, 7)
	for i := range groups {
		groups[i] = models.SELinuxAVCGroup{Scontext: "t", Tcontext: "t", Tclass: "file", Count: 1}
	}
	info := &models.SecurityInfo{SELinuxMode: "enforcing", SELinuxAVCGroups: groups}
	out := captureStdout(t, func() { printSELinuxSection(info, output.ModePlain) })
	if !strings.Contains(out, "and 2 more group(s)") {
		t.Errorf("more than 5 AVC groups should be capped with a remainder count, got:\n%s", out)
	}
}

func TestPrintSELinuxSectionPortLabels(t *testing.T) {
	info := &models.SecurityInfo{
		SELinuxMode: "enforcing",
		SELinuxUnlabeledPorts: []models.SELinuxUnlabeledPort{
			{Port: 9999, Protocol: "tcp", Process: "myapp"},
			{Port: 8888, Protocol: "tcp"},
		},
	}
	out := captureStdout(t, func() { printSELinuxSection(info, output.ModePlain) })
	if !strings.Contains(out, "myapp") || !strings.Contains(out, "9999") {
		t.Errorf("an unlabeled port with a known process should show both, got:\n%s", out)
	}
	if !strings.Contains(out, "unknown process") {
		t.Errorf("an unlabeled port with no process name should say unknown process, got:\n%s", out)
	}
	if !strings.Contains(out, "semanage port -a") {
		t.Errorf("the semanage fix command should be shown, got:\n%s", out)
	}
}

func TestPrintSELinuxSectionFileContextIssues(t *testing.T) {
	info := &models.SecurityInfo{
		SELinuxMode: "enforcing",
		SELinuxContextIssues: []models.SELinuxContextIssue{
			{Path: "/srv/app/data", ActualContext: "unconfined_u:object_r:var_t:s0", ExpectedContext: "system_u:object_r:httpd_sys_content_t:s0"},
		},
	}
	out := captureStdout(t, func() { printSELinuxSection(info, output.ModePlain) })
	if !strings.Contains(out, "/srv/app/data") || !strings.Contains(out, "httpd_sys_content_t") {
		t.Errorf("a file context issue should show its path and expected type, got:\n%s", out)
	}
	if !strings.Contains(out, "semanage fcontext -a -t httpd_sys_content_t") {
		t.Errorf("the semanage fcontext fix command should use the extracted type, got:\n%s", out)
	}
}

func TestPrintAppArmorSectionDenialGroups(t *testing.T) {
	info := &models.SecurityInfo{
		AppArmorMode: "enforce", AppArmorProfiles: 5,
		AppArmorGroups: []models.AppArmorDenial{
			{Profile: "/usr/bin/nginx", Path: "/etc/secret", Count: 4},
		},
	}
	out := captureStdout(t, func() { printAppArmorSection(info, output.ModePlain) })
	if !strings.Contains(out, "/usr/bin/nginx") || !strings.Contains(out, "aa-logprof") {
		t.Errorf("a denial group should name the profile and suggest aa-logprof, got:\n%s", out)
	}
}

// TestPrintAppArmorSectionDenialGroupsCapped guards the ">3 denial group"
// truncation (only the first 3 are printed) — distinct from the single-group
// case in TestPrintAppArmorSectionDenialGroups above.
func TestPrintAppArmorSectionDenialGroupsCapped(t *testing.T) {
	info := &models.SecurityInfo{
		AppArmorMode: "enforce", AppArmorProfiles: 5,
		AppArmorGroups: []models.AppArmorDenial{
			{Profile: "/usr/bin/a", Path: "/etc/a", Count: 1},
			{Profile: "/usr/bin/b", Path: "/etc/b", Count: 2},
			{Profile: "/usr/bin/c", Path: "/etc/c", Count: 3},
			{Profile: "/usr/bin/d", Path: "/etc/d", Count: 4},
		},
	}
	out := captureStdout(t, func() { printAppArmorSection(info, output.ModePlain) })
	if strings.Contains(out, "/usr/bin/d") {
		t.Errorf("only the first 3 denial groups should be printed, got:\n%s", out)
	}
	if !strings.Contains(out, "4 denial group(s)") {
		t.Errorf("the full group count should still be reported, got:\n%s", out)
	}
}

func TestPrintAppArmorSectionBareDenials(t *testing.T) {
	info := &models.SecurityInfo{
		AppArmorMode: "enforce", AppArmorProfiles: 5, AppArmorDenials: 3,
	}
	out := captureStdout(t, func() { printAppArmorSection(info, output.ModePlain) })
	if !strings.Contains(out, "3 denial(s) in the last hour") {
		t.Errorf("bare denial counts (no groups) should still be reported, got:\n%s", out)
	}
}

func TestPrintAppArmorSectionAbsent(t *testing.T) {
	for _, mode := range []string{"", "disabled", "unknown"} {
		info := &models.SecurityInfo{AppArmorMode: mode}
		out := captureStdout(t, func() { printAppArmorSection(info, output.ModePlain) })
		if out != "" {
			t.Errorf("AppArmorMode=%q should print nothing, got:\n%s", mode, out)
		}
	}
}

// TestPrintFirewallSectionServices guards the "allowed:" line, which needs
// FirewallServices populated on top of FirewallActive.
func TestPrintFirewallSectionServices(t *testing.T) {
	info := &models.SecurityInfo{
		FirewallActive: true, FirewallType: "firewalld", SSHAllowed: true,
		FirewallServices: []string{"ssh", "http", "https"},
	}
	out := captureStdout(t, func() { printFirewallSection(info, output.ModePlain) })
	if !strings.Contains(out, "allowed: ssh, http, https") {
		t.Errorf("configured firewall services should be listed, got:\n%s", out)
	}
}

// TestPrintFirewallSectionZone covers the FirewallZone annotation (firewalld
// zones), a distinct branch from the plain active-firewall case above.
func TestPrintFirewallSectionZone(t *testing.T) {
	info := &models.SecurityInfo{
		FirewallActive: true, FirewallType: "firewalld", SSHAllowed: true,
		FirewallZone: "public",
	}
	out := captureStdout(t, func() { printFirewallSection(info, output.ModePlain) })
	if !strings.Contains(out, "(zone: public)") {
		t.Errorf("a set FirewallZone should be shown, got:\n%s", out)
	}
}

// TestPrintPAMSectionCapped guards the ">=5 module failures" truncation.
func TestPrintPAMSectionCapped(t *testing.T) {
	failures := make([]models.PAMFailure, 7)
	for i := range failures {
		failures[i] = models.PAMFailure{Service: "sudo", User: "u", Count: 1}
	}
	info := &models.SecurityInfo{PAMModuleFailures: failures}
	out := captureStdout(t, func() { printPAMSection(info, output.ModePlain) })
	if !strings.Contains(out, "and 2 more") {
		t.Errorf("more than 5 module failures should be capped with a remainder count, got:\n%s", out)
	}
}
