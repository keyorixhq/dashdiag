package drilldown

import (
	"reflect"
	"sort"
	"testing"
)

// TestParseAAStatusJSON guards BUG-023: complain-mode names must come back clean
// (Xorg), never with JSON punctuation attached ("Xorg":).
func TestParseAAStatusJSON(t *testing.T) {
	out := `{
  "version": "1.1",
  "profiles": {
    "/usr/bin/man": "enforce",
    "Xorg": "complain",
    "plasmashell": "complain",
    "sbuild": "complain",
    "/usr/sbin/cups-browsed": "enforce"
  },
  "processes": {}
}`
	names, ok := parseAAStatusJSON(out)
	if !ok {
		t.Fatal("expected JSON to parse")
	}
	sort.Strings(names)
	want := []string{"Xorg", "plasmashell", "sbuild"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("got %v, want %v", names, want)
	}
}

func TestParseAAStatusJSONRejectsNonJSON(t *testing.T) {
	if _, ok := parseAAStatusJSON("apparmor module is loaded.\n23 profiles are in complain mode."); ok {
		t.Error("plain text must not parse as the JSON shape")
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
