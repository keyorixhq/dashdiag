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

// TestStatusSymbol_StripsControlChars guards terminal escape injection: an
// unrecognized status string (or --plain's verbatim pass-through) comes
// straight from a remote host's dsd health --json body, which a compromised
// or hostile fleet member fully controls.
func TestStatusSymbol_StripsControlChars(t *testing.T) {
	evil := "evil\x1b]0;pwned\x07"
	for _, plain := range []bool{true, false} {
		got := statusSymbol(evil, plain)
		if strings.Contains(got, "\x1b") {
			t.Errorf("statusSymbol(evil, plain=%v) still contains ESC byte: %q", plain, got)
		}
	}
}

// TestPrintCompare_StripsControlChars guards terminal escape injection: a
// remote host's `dsd health --json` snapshot fully controls Hostname and
// per-check Name/Status, and dsd compare is explicitly meant to be fed
// snapshots from other (possibly hostile) hosts.
func TestPrintCompare_StripsControlChars(t *testing.T) {
	// Three hosts (not two) so printOutlierAnalysis's own Hostname print site
	// also gets exercised — it needs >= 3 to fire.
	snaps := []*compareSnapshot{
		{
			Hostname:  "evil\x1b]0;pwned\x07",
			Timestamp: "2026-01-01T00:00:00Z",
			Checks:    []compareCheck{{Name: "check\x1b[31mred\x1b[0m", Status: "OK"}},
		},
		{
			Hostname:  "host2",
			Timestamp: "2026-01-01T00:00:00Z",
			Checks:    []compareCheck{{Name: "check\x1b[31mred\x1b[0m", Status: "WARN"}},
		},
		{
			Hostname:  "host3",
			Timestamp: "2026-01-01T00:00:00Z",
			Checks:    []compareCheck{{Name: "check\x1b[31mred\x1b[0m", Status: "WARN"}},
		},
	}
	out := captureStdout(t, func() {
		printCompare(snaps, true, true)
	})
	if strings.Contains(out, "\x1b") {
		t.Errorf("printCompare output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil]0;pwned") || !strings.Contains(out, "check[31mred[0m") {
		t.Errorf("printCompare output missing sanitized hostname/check name:\n%s", out)
	}
	if !strings.Contains(out, "Outlier") {
		t.Fatalf("test setup bug: outlier line did not fire, got:\n%s", out)
	}
}
