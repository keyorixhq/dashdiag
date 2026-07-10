package collectors

import (
	"testing"
	"time"
)

// TestParseZFSSize guards the human-readable-size-to-GB conversion — the
// project's own history has multiple ZFS parser bugs (vdev-count negative
// cancels a real error, etc.), so this is a historically bug-prone parser.
func TestParseZFSSize(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s    string
		want float64
	}{
		{"100G", 100},
		{"2T", 2048},
		{"-", 0},
		{"", 0},
		{"512M", 0.5},
		{"1024K", 1024.0 / (1024 * 1024)},
		{"3P", 3 * 1024 * 1024},
		{"5368709120", 5368709120.0 / (1024 * 1024 * 1024)}, // raw bytes, no unit suffix
		{"not-a-size", 0}, // unparsable, no known suffix
		{"12X", 0},        // unknown unit suffix
		{"  100G  ", 100}, // surrounding whitespace trimmed
		{"100g", 100},     // lower-case unit still recognized
		{"XG", 0},         // known unit suffix, but the numeric part is garbled
	}
	for _, c := range cases {
		if got := parseZFSSize(c.s); got != c.want {
			t.Errorf("parseZFSSize(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestParseZFSInt(t *testing.T) {
	if got := parseZFSInt("23"); got != 23 {
		t.Errorf("parseZFSInt(23) = %d", got)
	}
	if got := parseZFSInt("not a number"); got != 0 {
		t.Errorf("a garbled int should return 0, got %d", got)
	}
}

// TestParseZpoolList guards the exact column order the collector requests via
// `zpool list -H -o name,size,free,frag,cap,health` (tab-separated, no
// header) — the -o flag pins this order, so the test fixture must match it
// exactly rather than a default `zpool list`'s wider column set.
func TestParseZpoolList(t *testing.T) {
	out := "tank\t100G\t40G\t23%\t45%\tONLINE\n" +
		"backup\t2T\t-\t-\t100%\tDEGRADED\n"
	pools := parseZpoolList(out)

	tank, ok := pools["tank"]
	if !ok {
		t.Fatal("the tank pool should be parsed")
	}
	if tank.SizeGB != 100 || tank.FreeGB != 40 {
		t.Errorf("tank size/free wrong: %+v", tank)
	}
	if tank.FragPct != 23 {
		t.Errorf("tank frag%% should be 23, got %d", tank.FragPct)
	}
	// cap% (45) overrides the computed (size-free)/size — cap is the more
	// accurate real ZFS-reported usage figure.
	if tank.UsedPct != 45 {
		t.Errorf("tank UsedPct should come from cap%%, got %v", tank.UsedPct)
	}
	if tank.State != "ONLINE" {
		t.Errorf("tank state should be ONLINE, got %q", tank.State)
	}

	backup, ok := pools["backup"]
	if !ok {
		t.Fatal("the backup pool should be parsed")
	}
	if backup.State != "DEGRADED" {
		t.Errorf("backup state should be DEGRADED, got %q", backup.State)
	}
	if backup.UsedPct != 100 {
		t.Errorf("backup cap%% (100) should be used as UsedPct even with free=-, got %v", backup.UsedPct)
	}
}

func TestParseScrubAge(t *testing.T) {
	t.Parallel()
	// Real zpool status format: "scan: scrub repaired 0B in 00:12:34 with 0 errors on Sun May 12 03:25:01 2024"
	line := "scan: scrub repaired 0B in 00:12:34 with 0 errors on Sun May 12 03:25:01 2024"
	if got := parseScrubAge(line); got < 0 {
		t.Errorf("a well-formed scrub line should parse a non-negative age, got %d", got)
	}
	if got := parseScrubAge("no 'on' keyword here"); got != -1 {
		t.Errorf("a line with no ' on ' marker should return -1 (never scrubbed / unknown), got %d", got)
	}
	// Some zpool versions omit the weekday name — must still parse via the
	// no-weekday fallback layout ("Jan 2 15:04:05 2006").
	if got := parseScrubAge("scan: scrub repaired 0B in 00:01:23 with 0 errors on May 12 03:25:01 2024"); got < 0 {
		t.Errorf("a weekday-less date should still parse a non-negative age, got %d", got)
	}
	// Neither layout matches (garbled date) — must return 0, not -1 or a panic.
	if got := parseScrubAge("scan: scrub repaired 0B in 00:01:23 with 0 errors on not-a-real-date"); got != 0 {
		t.Errorf("an unparsable date after ' on ' should return 0, got %d", got)
	}
	// A future-dated scrub (clock skew) must clamp to 0, never a negative age.
	future := time.Now().Add(48 * time.Hour).Format("Mon Jan 2 15:04:05 2006")
	if got := parseScrubAge("scan: scrub repaired 0B in 00:01:23 with 0 errors on " + future); got != 0 {
		t.Errorf("a future scrub date must clamp to age=0, got %d", got)
	}
}

func TestParseScrubErrors(t *testing.T) {
	t.Parallel()
	line := "scan: scrub repaired 0B in 00:12:34 with 3 errors on Sun May 12 03:25:01 2024"
	if got := parseScrubErrors(line); got != 3 {
		t.Errorf("parseScrubErrors should extract the count after 'with', got %d", got)
	}
	if got := parseScrubErrors("no with keyword"); got != 0 {
		t.Errorf("a line with no ' with ' marker should return 0, got %d", got)
	}
	// Genuinely no " with " substring anywhere in the line — hits the
	// strings.Cut ok=false branch directly (the "no with keyword" case above
	// actually DOES contain the " with " substring and takes the happy path).
	if got := parseScrubErrors("scan: scrub repaired 0B in 00:12:34, no errors found"); got != 0 {
		t.Errorf("a line lacking the ' with ' substring entirely should return 0, got %d", got)
	}
	// " with " present but nothing follows it — no fields to read.
	if got := parseScrubErrors("scan: scrub repaired 0B in 00:12:34 with "); got != 0 {
		t.Errorf("a ' with ' marker with no trailing fields should return 0, got %d", got)
	}
	// " with " present but the first token isn't a count (garbled) — parseZFSInt
	// itself returns 0 on a bad parse, so this must also be 0.
	if got := parseScrubErrors("scan: scrub repaired 0B in 00:12:34 with lots of errors"); got != 0 {
		t.Errorf("a non-numeric token after 'with' should return 0, got %d", got)
	}
}
