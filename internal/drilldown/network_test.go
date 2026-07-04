package drilldown

import "testing"

// TestParseSSProc guards the users:(("name",pid=N,fd=N)) extraction.
func TestParseSSProc(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`users:(("nginx",pid=1234,fd=5))`, "nginx[1234]"},
		{`users:(("sshd",pid=42,fd=3),("sshd",pid=42,fd=4))`, "sshd[42]"},
		{"", ""},
		{"users:", ""},
	}
	for _, c := range cases {
		if got := parseSSProc(c.in); got != c.want {
			t.Errorf("parseSSProc(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestParseSsOutputRootAttribution guards the base case: as root (or with
// full access), CLOSE_WAIT/TIME_WAIT rows are attributed per-process and no
// caveat is added.
func TestParseSsOutputRootAttribution(t *testing.T) {
	out := "CLOSE-WAIT 0 0   127.0.0.1:8080   127.0.0.1:5000   users:((\"nginx\",pid=100,fd=5))\n" +
		"ESTAB      0 0   127.0.0.1:8080   127.0.0.1:5001   users:((\"nginx\",pid=100,fd=6))\n"
	d := parseSsOutput(out, false)
	if d.Note != "" {
		t.Errorf("root/full-access attribution should carry no caveat, got %q", d.Note)
	}
	if len(d.Rows) != 1 || d.Rows[0][0] != "nginx[100]" || d.Rows[0][1] != "CLOSE_WAIT" {
		t.Errorf("expected one CLOSE_WAIT row for nginx[100], got %+v", d.Rows)
	}
	if d.KV["CLOSE-WAIT"] != "1" || d.KV["ESTAB"] != "1" {
		t.Errorf("state counts wrong: %+v", d.KV)
	}
}

// TestParseSsOutputNonRootCaveat guards the false-OK-by-omission fix: `ss
// -tnp` only reports the users:(...) owner field for sockets the caller
// owns, so an unprivileged run silently drops other users' connections from
// the per-process tables with no indication. nonRoot=true must now attach an
// honest caveat, matching the /proc/net/tcp fallback's existing note.
func TestParseSsOutputNonRootCaveat(t *testing.T) {
	out := "CLOSE-WAIT 0 0   127.0.0.1:8080   127.0.0.1:5000   users:((\"nginx\",pid=100,fd=5))\n"
	d := parseSsOutput(out, true)
	if d.Note != procAttrNote {
		t.Errorf("expected the shared per-process-attribution caveat, got %q", d.Note)
	}
}
