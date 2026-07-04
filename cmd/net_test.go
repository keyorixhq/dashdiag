package cmd

import "testing"

func TestBandLabel(t *testing.T) {
	cases := []struct {
		ghz  float64
		want string
	}{
		{2.4, "2.4GHz"},
		{5, "5GHz"},
		{6, "6GHz"},
		{3.7, "unknown"},
	}
	for _, c := range cases {
		if got := bandLabel(c.ghz); got != c.want {
			t.Errorf("bandLabel(%v) = %q, want %q", c.ghz, got, c.want)
		}
	}
}

func TestIconBand(t *testing.T) {
	// 2.4GHz is flagged (crowded/legacy band); 5/6GHz are not.
	if got := iconBand(2.4); got != "⚠️ " {
		t.Errorf("iconBand(2.4) = %q, want warn", got)
	}
	if got := iconBand(5); got != "✅" {
		t.Errorf("iconBand(5) = %q, want ok", got)
	}
}

func TestIconWidth(t *testing.T) {
	// A 20MHz channel width is the flagged case (narrow/legacy); wider is fine.
	if got := iconWidth(20); got != "⚠️ " {
		t.Errorf("iconWidth(20) = %q, want warn", got)
	}
	if got := iconWidth(80); got != "✅" {
		t.Errorf("iconWidth(80) = %q, want ok", got)
	}
}

func TestIconSignal(t *testing.T) {
	cases := []struct {
		dbm  int
		want string
	}{
		{-50, "✅"},
		{-65, "⚠️ "},
		{-70, "⚠️ "},
		{-76, "❌"},
	}
	for _, c := range cases {
		if got := iconSignal(c.dbm); got != c.want {
			t.Errorf("iconSignal(%d) = %q, want %q", c.dbm, got, c.want)
		}
	}
}
