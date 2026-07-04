package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/output"
)

func TestRaucIcon(t *testing.T) {
	cases := []struct {
		status string
		want   string
	}{
		{"bad", "CRIT"},
		{"BAD", "CRIT"}, // case-insensitive
		{"", "INFO"},    // no slot state read
		{"good", "OK"},
	}
	for _, c := range cases {
		got := strings.TrimSpace(raucIcon(c.status, output.ModePlain))
		if got != c.want {
			t.Errorf("raucIcon(%q) = %q, want %q", c.status, got, c.want)
		}
	}
}

func TestUsageIcon(t *testing.T) {
	cases := []struct {
		pct, warn, crit float64
		want            string
	}{
		{10, 70, 90, "OK"},
		{70, 70, 90, "WARN"},
		{90, 70, 90, "CRIT"},
	}
	for _, c := range cases {
		got := strings.TrimSpace(usageIcon(c.pct, c.warn, c.crit, output.ModePlain))
		if got != c.want {
			t.Errorf("usageIcon(%v, warn=%v, crit=%v) = %q, want %q", c.pct, c.warn, c.crit, got, c.want)
		}
	}
}

func TestActiveIconAndWord(t *testing.T) {
	if got := strings.TrimSpace(activeIcon(true, output.ModePlain)); got != "OK" {
		t.Errorf("activeIcon(true) = %q, want OK", got)
	}
	if got := strings.TrimSpace(activeIcon(false, output.ModePlain)); got != "WARN" {
		t.Errorf("activeIcon(false) = %q, want WARN", got)
	}
	if got := activeWord(true); got != "active" {
		t.Errorf("activeWord(true) = %q, want active", got)
	}
	if got := activeWord(false); got != "inactive" {
		t.Errorf("activeWord(false) = %q, want inactive", got)
	}
}
