package cmd

import (
	"reflect"
	"strings"
	"testing"
)

func TestCollectCheckNames(t *testing.T) {
	snaps := []*compareSnapshot{
		{Checks: []compareCheck{{Name: "Disk"}, {Name: "CPU"}}},
		{Checks: []compareCheck{{Name: "CPU"}, {Name: "Network"}}},
	}
	got := collectCheckNames(snaps)
	want := []string{"CPU", "Disk", "Network"} // dedup'd + sorted
	if !reflect.DeepEqual(got, want) {
		t.Errorf("collectCheckNames = %v, want %v", got, want)
	}
}

func TestBuildStatusMatrix(t *testing.T) {
	snaps := []*compareSnapshot{
		{Checks: []compareCheck{{Name: "Disk", Status: "OK"}}},
		{Checks: []compareCheck{{Name: "Disk", Status: "WARN"}}},
	}
	m := buildStatusMatrix(snaps, []string{"Disk", "Missing"})

	if got := m["Disk"]; !reflect.DeepEqual(got, []string{"OK", "WARN"}) {
		t.Errorf("Disk statuses = %v, want [OK WARN]", got)
	}
	// A check absent from a host's snapshot must show as "not present", not
	// silently drop the column or default to an empty string that could be
	// misread as a real (empty) status.
	if got := m["Missing"]; !reflect.DeepEqual(got, []string{"—", "—"}) {
		t.Errorf("Missing statuses = %v, want [— —]", got)
	}
}

func TestStatusesDiffer(t *testing.T) {
	cases := []struct {
		name     string
		statuses []string
		want     bool
	}{
		{"empty", nil, false},
		{"single", []string{"OK"}, false},
		{"all same", []string{"OK", "OK", "OK"}, false},
		{"differ", []string{"OK", "WARN", "OK"}, true},
	}
	for _, c := range cases {
		if got := statusesDiffer(c.statuses); got != c.want {
			t.Errorf("%s: statusesDiffer(%v) = %v, want %v", c.name, c.statuses, got, c.want)
		}
	}
}

func TestStatusSymbol(t *testing.T) {
	// --plain must return the raw status verbatim (no emoji leaking into
	// machine-parseable output).
	if got := statusSymbol("CRIT", true); got != "CRIT" {
		t.Errorf("plain mode: statusSymbol(CRIT) = %q, want CRIT", got)
	}
	// Human mode adds an icon but must still contain the status word so a
	// reader (or a substring-matching test) never loses the actual verdict.
	for _, level := range []string{"OK", "WARN", "CRIT", "INFO"} {
		got := statusSymbol(level, false)
		if !strings.Contains(got, level) {
			t.Errorf("statusSymbol(%s) = %q, missing the level text", level, got)
		}
	}
	// An unrecognized status must pass through unchanged rather than being
	// swallowed into one of the known icons.
	if got := statusSymbol("WEIRD", false); got != "WEIRD" {
		t.Errorf("statusSymbol(WEIRD) = %q, want WEIRD unchanged", got)
	}
}
