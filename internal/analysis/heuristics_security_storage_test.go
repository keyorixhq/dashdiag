package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Characterization tests for the security and storage heuristics — the WARN/CRIT
// thresholds that encode the actual diagnostic verdicts and must not silently
// drift. These check* functions are pure (models struct in, []Insight out).
// Reuses res/hasLevel/assertLevel from heuristics_test.go (same package).

// hasInsightMsg reports whether any insight has the given level AND a message
// containing substr — used to pin a *specific* condition in functions (like
// checkSecurity) that can emit many insights at once.
func hasInsightMsg(insights []models.Insight, level, substr string) bool {
	for _, ins := range insights {
		if ins.Level == level && strings.Contains(ins.Message, substr) {
			return true
		}
	}
	return false
}

// ── SSH hardening (checkSecurity) ─────────────────────────────────────────────

func TestCheckSecuritySSH(t *testing.T) {
	// Baseline with no findings so each case toggles exactly one condition.
	base := func() models.SecurityInfo {
		return models.SecurityInfo{SSHStrictModes: true, FirewallActive: true}
	}
	tests := []struct {
		name   string
		mutate func(*models.SecurityInfo)
		level  string
		msg    string
	}{
		{"root login is CRIT", func(s *models.SecurityInfo) { s.SSHPermitRoot = true }, "CRIT", "root login"},
		{"root login on PVE is INFO", func(s *models.SecurityInfo) { s.SSHPermitRoot = true; s.IsPVE = true }, "INFO", "PVE management"},
		{"root login on offensive distro is INFO", func(s *models.SecurityInfo) { s.SSHPermitRoot = true; s.IsOffensiveDistro = true }, "INFO", "offensive security distro"},
		{"password auth is WARN", func(s *models.SecurityInfo) { s.SSHPasswordAuth = true }, "WARN", "password authentication"},
		{"protocol 1 is CRIT", func(s *models.SecurityInfo) { s.SSHProtocol1 = true }, "CRIT", "Protocol 1"},
		{"empty passwords is CRIT", func(s *models.SecurityInfo) { s.SSHPermitEmptyPwd = true }, "CRIT", "empty passwords"},
		{"strictmodes off is WARN", func(s *models.SecurityInfo) { s.SSHStrictModes = false }, "WARN", "StrictModes"},
		{"high maxauthtries is WARN", func(s *models.SecurityInfo) { s.SSHMaxAuthTries = 8 }, "WARN", "MaxAuthTries"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sec := base()
			tt.mutate(&sec)
			got := checkSecurity(sec)
			if !hasInsightMsg(got, tt.level, tt.msg) {
				t.Errorf("want %s insight containing %q, got %+v", tt.level, tt.msg, got)
			}
		})
	}
}

func TestCheckSecuritySSH_RootCritNotPVE(t *testing.T) {
	// Guard the PVE/offensive downgrade: a plain host with root SSH must stay CRIT,
	// never INFO.
	got := checkSecurity(models.SecurityInfo{SSHPermitRoot: true, SSHStrictModes: true, FirewallActive: true})
	if hasInsightMsg(got, "INFO", "root") {
		t.Errorf("plain host root SSH must not be downgraded to INFO: %+v", got)
	}
	if !hasInsightMsg(got, "CRIT", "root login") {
		t.Errorf("plain host root SSH must be CRIT: %+v", got)
	}
}

// ── standalone security checks ────────────────────────────────────────────────

func TestCheckEmptyPasswords(t *testing.T) {
	assertLevel(t, checkEmptyPasswords(models.SecurityInfo{}), "")
	assertLevel(t, checkEmptyPasswords(models.SecurityInfo{EmptyPasswordAccounts: []string{"bob"}}), "CRIT")
}

func TestCheckStalePasswords(t *testing.T) {
	assertLevel(t, checkStalePasswords(models.SecurityInfo{}), "")
	assertLevel(t, checkStalePasswords(models.SecurityInfo{StalePasswordAccounts: []string{"alice"}}), "WARN")
}

func TestCheckWorldWritable(t *testing.T) {
	assertLevel(t, checkWorldWritable(models.SecurityInfo{}), "")
	assertLevel(t, checkWorldWritable(models.SecurityInfo{WorldWritableDirs: []string{"/tmp"}}), "CRIT")
}

func TestCheckSSHWeakCiphers(t *testing.T) {
	assertLevel(t, checkSSHWeakCiphers(models.SecurityInfo{}), "") // not configured
	assertLevel(t, checkSSHWeakCiphers(models.SecurityInfo{
		SSHCiphers: "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
	}), "") // strong only
	assertLevel(t, checkSSHWeakCiphers(models.SecurityInfo{
		SSHCiphers: "aes256-cbc,aes256-gcm@openssh.com",
	}), "WARN") // CBC present
}

// ── ZFS pool thresholds ───────────────────────────────────────────────────────

func TestCheckZFSPool(t *testing.T) {
	tests := []struct {
		name   string
		pool   models.ZFSPool
		want   string // expected level; "" = no insights
		forbid string // a level that must NOT appear ("" = no check)
	}{
		{"online and clean", models.ZFSPool{Name: "tank", State: "ONLINE", UsedPct: 50, FragPct: 10, ScrubAgeDays: 5}, "", ""},
		{"degraded is CRIT", models.ZFSPool{Name: "tank", State: "DEGRADED", ScrubAgeDays: 5}, "CRIT", ""},
		{"faulted is CRIT", models.ZFSPool{Name: "tank", State: "FAULTED", ScrubAgeDays: 5}, "CRIT", ""},
		{"unavail is CRIT", models.ZFSPool{Name: "tank", State: "UNAVAIL", ScrubAgeDays: 5}, "CRIT", ""},
		{"85pct full is WARN not CRIT", models.ZFSPool{Name: "tank", State: "ONLINE", UsedPct: 85, ScrubAgeDays: 5}, "WARN", "CRIT"},
		{"92pct full is CRIT", models.ZFSPool{Name: "tank", State: "ONLINE", UsedPct: 92, ScrubAgeDays: 5}, "CRIT", ""},
		{"high fragmentation is WARN", models.ZFSPool{Name: "tank", State: "ONLINE", UsedPct: 10, FragPct: 75, ScrubAgeDays: 5}, "WARN", ""},
		// Cumulative vdev errors on a healthy ONLINE pool with a clean last scrub are
		// repaired/transient — WARN, not a perpetual CRIT (real corruption signals below).
		{"repaired checksum errors on healthy pool is WARN not CRIT", models.ZFSPool{Name: "tank", State: "ONLINE", UsedPct: 10, CksumErrors: 3, ScrubAgeDays: 5}, "WARN", "CRIT"},
		{"vdev errors on degraded pool is CRIT", models.ZFSPool{Name: "tank", State: "DEGRADED", UsedPct: 10, CksumErrors: 3, ScrubAgeDays: 5}, "CRIT", ""},
		{"vdev errors with unrepairable scrub is CRIT", models.ZFSPool{Name: "tank", State: "ONLINE", UsedPct: 10, CksumErrors: 3, ScrubErrors: 2, ScrubAgeDays: 5}, "CRIT", ""},
		{"never scrubbed is WARN", models.ZFSPool{Name: "tank", State: "ONLINE", UsedPct: 10, ScrubAgeDays: -1}, "WARN", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkZFSPool(tt.pool)
			assertLevel(t, got, tt.want)
			if tt.forbid != "" && hasLevel(got, tt.forbid) {
				t.Errorf("did not expect level %q, got %+v", tt.forbid, got)
			}
		})
	}
}

// ── mdadm RAID states ─────────────────────────────────────────────────────────

func TestCheckRAID(t *testing.T) {
	arr := func(state string) models.RAIDInfo {
		return models.RAIDInfo{Arrays: []models.RAIDDevice{
			{Name: "md0", Level: "raid5", State: state, Active: 2, Total: 3, Failed: []string{"sdb"}, RebuildPct: 42},
		}}
	}
	tests := []struct {
		state string
		want  string
	}{
		{"active", ""}, // healthy -> no insight
		{"degraded", "CRIT"},
		{"recovering", "WARN"},
		{"failed", "CRIT"},
	}
	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			assertLevel(t, checkRAID(arr(tt.state)), tt.want)
		})
	}
}
