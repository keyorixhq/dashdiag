package cmd

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

func TestPVETaskErrorCritTypes(t *testing.T) {
	t.Parallel()
	errs := []models.PVETaskError{
		{Type: "vzdump"}, {Type: "vzdump"}, {Type: "vzdump"}, // 3 → CRIT
		{Type: "qmigrate"}, {Type: "qmigrate"}, // 2 → not CRIT
		{Type: "vzsnapshot"}, // 1 → not CRIT
	}
	crit := pveTaskErrorCritTypes(errs)
	if !crit["vzdump"] {
		t.Error("vzdump (3 errors) should be CRIT")
	}
	if crit["qmigrate"] {
		t.Error("qmigrate (2 errors) should NOT be CRIT")
	}
	if crit["vzsnapshot"] {
		t.Error("vzsnapshot (1 error) should NOT be CRIT")
	}
	if got := len(pveTaskErrorCritTypes(nil)); got != 0 {
		t.Errorf("nil errors → %d crit types, want 0", got)
	}
}

func TestFormatPVEUptime(t *testing.T) {
	t.Parallel()
	cases := []struct {
		sec  int64
		want string
	}{
		{30, "0 minutes"},
		{300, "5 minutes"},
		{3600, "1 hours"},
		{7200, "2 hours"},
		{86400, "1 days"},
		{14 * 86400, "14 days"},
	}
	for _, c := range cases {
		if got := formatPVEUptime(c.sec); got != c.want {
			t.Errorf("formatPVEUptime(%d) = %q, want %q", c.sec, got, c.want)
		}
	}
}

func TestPVEBackupIconAge(t *testing.T) {
	t.Parallel()
	cases := []struct {
		days     int
		wantIcon string
		wantAge  string
	}{
		{-1, "❌", "never"},
		{0, "✅", "today"},
		{1, "✅", "1 day ago"},
		{7, "✅", "7 days ago"},
		{8, "⚠️ ", "8 days ago"},
		{30, "⚠️ ", "30 days ago"},
		{31, "❌", "31 days ago"},
		{45, "❌", "45 days ago"},
	}
	for _, c := range cases {
		icon, age := pveBackupIconAge(c.days, output.ModeHuman)
		if icon != c.wantIcon || age != c.wantAge {
			t.Errorf("pveBackupIconAge(%d) = (%q,%q), want (%q,%q)", c.days, icon, age, c.wantIcon, c.wantAge)
		}
		// In plain mode the icon must be an ASCII token, never an emoji.
		plainIcon, _ := pveBackupIconAge(c.days, output.ModePlain)
		for _, g := range []string{"❌", "⚠️", "✅"} {
			if plainIcon == g {
				t.Errorf("pveBackupIconAge(%d) plain leaked emoji %q", c.days, g)
			}
		}
	}
}
