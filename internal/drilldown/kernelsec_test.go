package drilldown

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestParseAAStatusJSON guards BUG-023 (complain-mode names must come back clean
// — Xorg, never "Xorg": with JSON punctuation attached) AND the determinism
// contract: the function must return names sorted, because doc.Profiles is a Go
// map. Without the sort the complain list ordered differently each run, making
// deep capture/replay non-byte-stable and producing spurious `dsd diff` deltas.
// We deliberately do NOT sort here — we assert the function already did.
func TestParseAAStatusJSON(t *testing.T) {
	out := `{
  "version": "1.1",
  "profiles": {
    "/usr/bin/man": "enforce",
    "sbuild": "complain",
    "Xorg": "complain",
    "plasmashell": "complain",
    "/usr/sbin/cups-browsed": "enforce"
  },
  "processes": {}
}`
	names, ok := parseAAStatusJSON(out)
	if !ok {
		t.Fatal("expected JSON to parse")
	}
	want := []string{"Xorg", "plasmashell", "sbuild"} // ASCII-sorted: 'X' < 'p' < 's'
	if !reflect.DeepEqual(names, want) {
		t.Errorf("parseAAStatusJSON not sorted: got %v, want %v", names, want)
	}
}

func TestParseAAStatusJSONRejectsNonJSON(t *testing.T) {
	if _, ok := parseAAStatusJSON("apparmor module is loaded.\n23 profiles are in complain mode."); ok {
		t.Error("plain text must not parse as the JSON shape")
	}
}

// TestBuildPolicyTableSELinuxEnforcingIsClean guards the Fedora CoreOS
// regression (2026-06-29): on a fully SELinux-enforcing host with no AppArmor,
// the "not in enforcing mode" detail must be EMPTY. The old code enumerated
// every SELinux boolean reporting "on" as "SELinux policy relaxed", so an
// enforcing host showed ~64 healthy booleans as non-enforcing policies plus an
// AppArmor `aa-status` hint that does not apply to SELinux.
func TestBuildPolicyTableSELinuxEnforcingIsClean(t *testing.T) {
	if d := buildPolicyTable(nil, "enforcing"); d != nil {
		t.Errorf("enforcing SELinux + no AppArmor must yield no table, got %+v", d)
	}
}

// TestBuildPolicyTableNeverListsBooleans is the structural guard: a boolean set
// to "on" is not a relaxed policy and must never appear. We assert no row uses
// the old "on" mode or "SELinux policy relaxed" note, across the genuinely
// non-enforcing states.
func TestBuildPolicyTableNeverListsBooleans(t *testing.T) {
	for _, mode := range []string{"enforcing", "permissive", "disabled", ""} {
		d := buildPolicyTable([]string{"sbuild"}, mode)
		if d == nil {
			continue
		}
		for _, row := range d.Rows {
			if row[1] == "on" || strings.Contains(row[2], "policy relaxed") {
				t.Errorf("mode %q: leaked a boolean-style row %v", mode, row)
			}
		}
		if strings.Contains(d.Note, "aa-status | grep complain") {
			t.Errorf("mode %q: note still hardcodes the AppArmor-only hint: %q", mode, d.Note)
		}
	}
}

func TestBuildPolicyTableSELinuxPermissive(t *testing.T) {
	d := buildPolicyTable(nil, "permissive")
	if d == nil {
		t.Fatal("permissive SELinux must surface a row")
	}
	if len(d.Rows) != 1 || d.Rows[0][0] != "SELinux" || d.Rows[0][1] != "permissive" {
		t.Errorf("unexpected permissive row: %+v", d.Rows)
	}
}

func TestBuildPolicyTableAppArmorComplain(t *testing.T) {
	d := buildPolicyTable([]string{"Xorg", "sbuild"}, "enforcing")
	if d == nil || len(d.Rows) != 2 {
		t.Fatalf("expected 2 AppArmor complain rows, got %+v", d)
	}
	for _, row := range d.Rows {
		if row[1] != "complain" {
			t.Errorf("AppArmor row must be complain mode: %v", row)
		}
	}
}

func TestParseAAStatusText(t *testing.T) {
	out := `apparmor module is loaded.
106 profiles are loaded.
83 profiles are in enforce mode.
   /usr/bin/man
   /usr/sbin/cupsd
23 profiles are in complain mode.
   Xorg
   plasmashell
   sbuild
0 profiles are in kill mode.
2 processes have profiles defined.
2 processes are in enforce mode.
   /usr/sbin/cupsd (1234)
0 processes are in complain mode.`
	names := parseAAStatusText(out)
	sort.Strings(names)
	want := []string{"Xorg", "plasmashell", "sbuild"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("got %v, want %v", names, want)
	}
}
