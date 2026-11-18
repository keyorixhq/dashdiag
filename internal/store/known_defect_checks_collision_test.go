package store

import (
	"os"
	"testing"
)

// TestParseStoreLine_SanitizedCheckKeyCollisionIsDeterministic pins DS1-F5:
// validateEntry rebuilds Checks with control characters stripped from the
// keys, so "disk" and "disk\a" collapse into one key and whichever status
// the map iteration visits last wins. The same store line then reads back as
// disk=OK on one run and disk=CRIT on the next (dsd history / dsd diff).
//
// Skipped unless DSD_KNOWN_DEFECTS=1 (not a production fix in this branch).
//
// What it does NOT verify: which status a fix should keep (the worst one is
// the conservative choice), or collisions through other normalisation.
func TestParseStoreLine_SanitizedCheckKeyCollisionIsDeterministic(t *testing.T) {
	if os.Getenv("DSD_KNOWN_DEFECTS") != "1" {
		t.Skip("DS1-F5 known defect; set DSD_KNOWN_DEFECTS=1 to run")
	}
	line := []byte(`{"verdict":"OK","checks":{"disk":"OK","disk\u0007":"CRIT"}}`)
	seen := map[string]bool{}
	for range 64 {
		e, ok := parseStoreLine(line)
		if !ok {
			t.Fatal("line rejected")
		}
		seen[e.Checks["disk"]] = true
	}
	if len(seen) != 1 {
		t.Fatalf("the same store line decodes to different statuses for check \"disk\": %v", seen)
	}
}
