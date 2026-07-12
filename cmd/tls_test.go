//go:build linux || darwin

package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/output"
)

func TestLevelIcon(t *testing.T) {
	cases := []struct {
		level string
		want  string
	}{
		{"CRIT", "CRIT"},
		{"WARN", "WARN"},
		{"OK", "OK"},
		{"whatever", "INFO"},
	}
	for _, c := range cases {
		got := strings.TrimSpace(levelIcon(c.level, output.ModePlain))
		if got != c.want {
			t.Errorf("levelIcon(%q) = %q, want %q", c.level, got, c.want)
		}
	}
}

// buildTLSInfo (the --json path) must NOT drop ERR results. An unreachable
// endpoint or unreadable cert is a cert we could not check — dropping it made
// `dsd tls --json` report 0 expired / 0 expiring with no trace of the failure,
// so a monitor read an unreachable host as healthy (false-OK).
func TestBuildTLSInfoRecordsUncheckable(t *testing.T) {
	results := []certResult{
		{Path: "good.example:443", Level: "OK", DaysLeft: 200, Remote: true},
		{Path: "down.example:443", Level: "ERR", Err: "dial tcp: connection refused", Remote: true},
	}
	ti := buildTLSInfo(results, []string{"good.example:443", "down.example:443"}, 30)

	if len(ti.Uncheckable) != 1 {
		t.Fatalf("uncheckable: got %d, want 1 (the unreachable endpoint must be recorded)", len(ti.Uncheckable))
	}
	if ti.Uncheckable[0].Path != "down.example:443" || ti.Uncheckable[0].Error == "" {
		t.Errorf("uncheckable entry not populated: %+v", ti.Uncheckable[0])
	}
	// One uncheckable, no expired/expiring → must be "warning", never "ok".
	if ti.Status != "warning" {
		t.Errorf("status with an uncheckable endpoint = %q, want warning (not a clean ok)", ti.Status)
	}
	if ti.StatusReason == "" {
		t.Errorf("status reason should explain the uncheckable count")
	}
}

func TestBuildTLSInfoStatusVerdicts(t *testing.T) {
	clean := buildTLSInfo([]certResult{{Path: "a", Level: "OK", DaysLeft: 100}}, nil, 30)
	if clean.Status != "ok" {
		t.Errorf("all-healthy status = %q, want ok", clean.Status)
	}
	expired := buildTLSInfo([]certResult{{Path: "a", Level: "CRIT", DaysLeft: -3}}, nil, 30)
	if expired.Status != "critical" || expired.Expired != 1 {
		t.Errorf("expired cert: status=%q expired=%d, want critical/1", expired.Status, expired.Expired)
	}

	// Positive DaysLeft but within the warn window (not yet expired) — a
	// distinct branch from both "clean" (DaysLeft > warnDays) and "expired"
	// (DaysLeft < 0) above.
	expiring := buildTLSInfo([]certResult{{Path: "a", Level: "WARN", DaysLeft: 10}}, nil, 30)
	if expiring.Status != "warning" || expiring.Expiring != 1 || expiring.Expired != 0 {
		t.Errorf("expiring-soon cert: status=%q expiring=%d expired=%d, want warning/1/0",
			expiring.Status, expiring.Expiring, expiring.Expired)
	}
}
