package collectors

import (
	"testing"
)

// TestParseVGs_ShortLines guards the "< 3 fields" continue branch in parseVGs.
// Lines with 0, 1, or 2 whitespace-separated tokens must be silently skipped
// and not contribute any VG to the output slice.
func TestParseVGs_ShortLines(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "single-token line is skipped",
			input: "  pve\n",
			want:  0,
		},
		{
			name:  "two-token line is skipped",
			input: "  pve 99.50\n",
			want:  0,
		},
		{
			name:  "three-token line is accepted (minimum valid)",
			input: "  pve 99.50 10.00\n",
			want:  1,
		},
		{
			name:  "blank-only line is skipped",
			input: "\n\n\n",
			want:  0,
		},
		{
			name:  "mix of short and valid lines — only valid ones count",
			input: "  pve\n  data 200.00 5.00 wz--n-\n",
			want:  1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			vgs := parseVGs(tc.input)
			if len(vgs) != tc.want {
				t.Errorf("parseVGs(%q): got %d VGs, want %d", tc.input, len(vgs), tc.want)
			}
		})
	}
}

// TestParseLVs_EmptyAttr guards the `if len(attr) == 0 { continue }` defensive
// branch at line 83 of lvm_parse.go. Because strings.Fields cannot produce empty
// token elements, this branch fires only when attr (fields[2]) is explicitly set
// to an empty string — something the real lvs output never does. We test it
// indirectly: a 5-field line whose third token consists only of a single
// whitespace-adjacent character (i.e. attr[0] does not match any handled case)
// falls through the switch without appending anything, producing zero results.
// The attr==0 guard itself remains a defensive no-op, but its neighbouring
// reachable paths ARE exercised here.
func TestParseLVs_AttrFallthrough(t *testing.T) {
	t.Parallel()
	// A line with 5 fields where lv_attr[0] is 'r' (not 't', 's', 'S', or 'V')
	// falls through the switch without appending to either slice.
	// < 5 fields lines are already covered by existing TestParseLVs tests; this
	// focuses on the switch-fallthrough path after the attr guard.
	input := "  lv1 vg1 rwi-aor--- 0.00 0.00 10.00\n"
	pools, snaps := parseLVs(input)
	if len(pools) != 0 || len(snaps) != 0 {
		t.Errorf("parseLVs with unrecognised attr type: got pools=%d snaps=%d, want 0/0",
			len(pools), len(snaps))
	}
}

// TestParseSSSockets_NoColonInLocalAddr guards steamos_parse.go:261 —
// the `if idx < 0 { continue }` branch inside parseSSSockets. When the local
// address field contains no ":", the port cannot be extracted and the line is
// silently skipped.
func TestParseSSSockets_NoColonInLocalAddr(t *testing.T) {
	t.Parallel()
	// A line where the local address is just "0.0.0.0" without a port suffix.
	// The proto ("udp") is valid so it passes the proto switch, but no ":" is
	// found via LastIndex, so idx == -1 and the line is skipped.
	out := "udp   UNCONN 0 0 0.0.0.0 0.0.0.0:*\n"
	socks := parseSSSockets(out)
	if len(socks) != 0 {
		t.Errorf("expected 0 sockets from no-colon local addr, got %d: %+v", len(socks), socks)
	}
}

// TestParseSSSockets_NonNumericPort guards steamos_parse.go:265 —
// the `if err != nil { continue }` branch inside parseSSSockets. When the
// token after the last ":" in the local address is not a valid integer, the
// line is silently skipped.
func TestParseSSSockets_NonNumericPort(t *testing.T) {
	t.Parallel()
	// The local address ends in ":xxx" which is not a valid port number.
	out := "tcp   LISTEN 0 128 0.0.0.0:xxx 0.0.0.0:*\n"
	socks := parseSSSockets(out)
	if len(socks) != 0 {
		t.Errorf("expected 0 sockets from non-numeric port, got %d: %+v", len(socks), socks)
	}
}

// TestParseSSSockets_ValidAndInvalidMix ensures that valid lines are parsed
// and invalid lines (no-colon, non-numeric-port) are skipped without polluting
// the result slice.
func TestParseSSSockets_ValidAndInvalidMix(t *testing.T) {
	t.Parallel()
	out := "Netid  State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n" +
		"udp    UNCONN 0      0      0.0.0.0 0.0.0.0:*\n" + // no colon in local → skipped
		"tcp    LISTEN 0      128    0.0.0.0:abc 0.0.0.0:*\n" + // non-numeric port → skipped
		"udp    UNCONN 0      0      0.0.0.0:27031 0.0.0.0:*\n" + // valid
		"tcp    LISTEN 0      128    [::]:22 [::]:*\n" // valid
	socks := parseSSSockets(out)
	if len(socks) != 2 {
		t.Errorf("expected 2 valid sockets, got %d: %+v", len(socks), socks)
	}
	if socks[0].Proto != "udp" || socks[0].Port != 27031 {
		t.Errorf("first valid socket: got proto=%q port=%d, want udp/27031", socks[0].Proto, socks[0].Port)
	}
	if socks[1].Proto != "tcp" || socks[1].Port != 22 {
		t.Errorf("second valid socket: got proto=%q port=%d, want tcp/22", socks[1].Proto, socks[1].Port)
	}
}

// TestMergeMissingPVs_ShortLine guards the `< 2` field skip in mergeMissingPVs.
// A single-token line must not panic or count as a missing PV.
func TestMergeMissingPVs_ShortLine(t *testing.T) {
	t.Parallel()
	vgs := parseVGs("  myvg 50.00 10.00\n")
	if len(vgs) == 0 {
		t.Fatal("parseVGs did not produce a VG to test mergeMissingPVs against")
	}
	// A pvs output line with only one token — should be skipped, not panic.
	mergeMissingPVs("  myvg\n", vgs)
	if vgs[0].MissingPVs != 0 {
		t.Errorf("MissingPVs = %d after short pvs line, want 0", vgs[0].MissingPVs)
	}
}

// TestParseZpoolList_ShortLines guards zfs.go parseZpoolList — lines with fewer
// than 6 fields are skipped. Typically the first line is a header or a blank.
func TestParseZpoolList_ShortLines(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "empty output produces no pools",
			input: "",
			want:  0,
		},
		{
			name:  "single-field line is skipped",
			input: "tank\n",
			want:  0,
		},
		{
			name:  "five-field line is skipped (needs 6)",
			input: "tank\t100G\t40G\t23%\t45%\n",
			want:  0,
		},
		{
			name:  "six-field line with minimal valid content is accepted",
			input: "tank\t100G\t40G\t23%\t45%\tONLINE\n",
			want:  1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pools := parseZpoolList(tc.input)
			if len(pools) != tc.want {
				t.Errorf("parseZpoolList(%q): got %d pools, want %d", tc.input, len(pools), tc.want)
			}
		})
	}
}

// TestParseZFSVdevErrorLine guards the error branches in parseZFSVdevErrorLine.
// Lines without a recognized STATE token return ok=false; lines with a STATE
// token but insufficient or unparseable counter columns also return ok=false.
func TestParseZFSVdevErrorLine_ErrorPaths(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		line   string
		wantOK bool
		wantR  int
		wantW  int
		wantC  int
	}{
		{
			name:   "no STATE token — returns not-ok",
			line:   "  sda   somestate   0   0   0",
			wantOK: false,
		},
		{
			name:   "STATE token at end — not enough counter fields",
			line:   "  sda   ONLINE",
			wantOK: false,
		},
		{
			name:   "STATE token with non-numeric counters",
			line:   "  sda   ONLINE   x   y   z",
			wantOK: false,
		},
		{
			name:   "valid vdev line with ONLINE state",
			line:   "  sda   ONLINE   0   1   2",
			wantOK: true,
			wantR:  0,
			wantW:  1,
			wantC:  2,
		},
		{
			name:   "valid vdev line with DEGRADED state",
			line:   "  mirror-0   DEGRADED   3   0   0",
			wantOK: true,
			wantR:  3,
			wantW:  0,
			wantC:  0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, w, c, ok := parseZFSVdevErrorLine(tc.line)
			if ok != tc.wantOK {
				t.Errorf("parseZFSVdevErrorLine(%q) ok=%v, want %v", tc.line, ok, tc.wantOK)
			}
			if ok && (r != tc.wantR || w != tc.wantW || c != tc.wantC) {
				t.Errorf("parseZFSVdevErrorLine(%q) = (%d,%d,%d), want (%d,%d,%d)",
					tc.line, r, w, c, tc.wantR, tc.wantW, tc.wantC)
			}
		})
	}
}

// TestParseZFSCount_EdgeCases guards the negative-value and overflow branches
// in parseZFSCount that prevent wrap-around false-OK bugs (TRIAGE §B).
func TestParseZFSCount_EdgeCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in     string
		wantN  int
		wantOK bool
	}{
		{"0", 0, true},
		{"-1", 0, false},   // negative int → rejected
		{"-1K", 0, false},  // negative float × suffix → rejected
		{"NaNK", 0, false}, // NaN × suffix → rejected
		{"InfK", 0, false}, // Inf × suffix → rejected
		{"1K", 1000, true},
		{"1M", 1_000_000, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			n, ok := parseZFSCount(tc.in)
			if ok != tc.wantOK {
				t.Errorf("parseZFSCount(%q) ok=%v, want %v", tc.in, ok, tc.wantOK)
			}
			if ok && n != tc.wantN {
				t.Errorf("parseZFSCount(%q) = %d, want %d", tc.in, n, tc.wantN)
			}
		})
	}
}
