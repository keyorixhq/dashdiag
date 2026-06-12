package explain

import (
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	tests := []struct {
		query   string
		wantKey string // "" = expect no single match
	}{
		{"swap", "swap"},
		{"SWAP", "swap"},    // case-insensitive
		{"ram", "memory"},   // alias
		{"zpool", "zfs"},    // alias
		{"  cpu  ", "cpu"},  // trimmed
		{"smart", "drives"}, // alias
		{"kev", "cve"},      // alias
		{"nonsense", ""},    // unknown
		{"", ""},            // empty
	}
	for _, tt := range tests {
		got, _ := Lookup(tt.query)
		if tt.wantKey == "" {
			if got != nil {
				t.Errorf("Lookup(%q) = %q, want no match", tt.query, got.Key)
			}
			continue
		}
		if got == nil || got.Key != tt.wantKey {
			t.Errorf("Lookup(%q) = %v, want %q", tt.query, got, tt.wantKey)
		}
	}
}

func TestLookupAmbiguous(t *testing.T) {
	// "disk" is a key (filesystem capacity) but "disk-io"/"diskio" are io aliases —
	// an exact key match must win cleanly, not report ambiguity.
	got, cands := Lookup("disk")
	if got == nil || got.Key != "disk" || len(cands) != 0 {
		t.Errorf("exact key 'disk' should resolve cleanly, got %v cands=%v", got, cands)
	}
}

func TestTopicsContentIntegrity(t *testing.T) {
	seen := map[string]bool{}
	for _, tp := range Topics() {
		if seen[tp.Key] {
			t.Errorf("duplicate topic key %q", tp.Key)
		}
		seen[tp.Key] = true
		if tp.Title == "" || tp.Summary == "" || tp.Checks == "" || tp.Matters == "" || tp.Verdict == "" {
			t.Errorf("topic %q is missing a required field", tp.Key)
		}
		if len(tp.Look) == 0 {
			t.Errorf("topic %q has no investigate commands", tp.Key)
		}
		// every alias must be lowercase and not collide with a key
		for _, a := range tp.Aliases {
			if a != strings.ToLower(a) {
				t.Errorf("topic %q alias %q must be lowercase", tp.Key, a)
			}
		}
	}
	if len(seen) < 10 {
		t.Errorf("expected a solid set of topics, got %d", len(seen))
	}
}

func TestForCheck(t *testing.T) {
	// Health Check names → explain topics (drives the `dsd health --explain` tail).
	tests := []struct {
		check   string
		wantKey string // "" = no topic
	}{
		{"Swap", "swap"},
		{"CPU Load", "cpu"},      // first-word fallback
		{"KernelSec", "selinux"}, // via alias
		{"ZFS", "zfs"},
		{"Network", "network"},
		{"Drives", "drives"},
		{"CVE", "cve"},
		{"Entropy", "entropy"},
		{"Subscription", ""}, // uncovered subsystem — must not panic or mis-map
	}
	for _, tt := range tests {
		got := ForCheck(tt.check)
		if tt.wantKey == "" {
			if got != nil {
				t.Errorf("ForCheck(%q) = %q, want nil", tt.check, got.Key)
			}
			continue
		}
		if got == nil || got.Key != tt.wantKey {
			t.Errorf("ForCheck(%q) = %v, want %q", tt.check, got, tt.wantKey)
		}
	}
}

func TestTopicsSorted(t *testing.T) {
	all := Topics()
	for i := 1; i < len(all); i++ {
		if all[i-1].Key > all[i].Key {
			t.Errorf("Topics() not sorted: %q before %q", all[i-1].Key, all[i].Key)
		}
	}
}
