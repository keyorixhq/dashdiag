package collectors

import "testing"

// TestParseZFSSize guards the human-readable-size-to-GB conversion — the
// project's own history has multiple ZFS parser bugs (vdev-count negative
// cancels a real error, etc.), so this is a historically bug-prone parser.
func TestParseZFSSize(t *testing.T) {
	cases := []struct {
		s    string
		want float64
	}{
		{"100G", 100},
		{"2T", 2048},
		{"-", 0},
		{"", 0},
		{"512M", 0.5},
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
	// Real zpool status format: "scan: scrub repaired 0B in 00:12:34 with 0 errors on Sun May 12 03:25:01 2024"
	line := "scan: scrub repaired 0B in 00:12:34 with 0 errors on Sun May 12 03:25:01 2024"
	if got := parseScrubAge(line); got < 0 {
		t.Errorf("a well-formed scrub line should parse a non-negative age, got %d", got)
	}
	if got := parseScrubAge("no 'on' keyword here"); got != -1 {
		t.Errorf("a line with no ' on ' marker should return -1 (never scrubbed / unknown), got %d", got)
	}
}

func TestParseScrubErrors(t *testing.T) {
	line := "scan: scrub repaired 0B in 00:12:34 with 3 errors on Sun May 12 03:25:01 2024"
	if got := parseScrubErrors(line); got != 3 {
		t.Errorf("parseScrubErrors should extract the count after 'with', got %d", got)
	}
	if got := parseScrubErrors("no with keyword"); got != 0 {
		t.Errorf("a line with no ' with ' marker should return 0, got %d", got)
	}
}
