package drilldown

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTCPStatesLinux_SsFailsFallsBackToProcNetTCP guards the fallback branch
// of tcpStatesLinux: when `ss` is unavailable/errors, it must fall through to
// the /proc/net/tcp reader (parseProcNetTCPAt) rather than propagating the ss
// error. tcpStatesLinux hardcodes "/proc/net", so this only asserts the
// fallback is actually invoked (no panic, honest Note) against the real
// container filesystem — parseProcNetTCPAt's own parsing logic is exercised
// against fixtures directly below.
func TestTCPStatesLinux_SsFailsFallsBackToProcNetTCP(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, _ ...string) (string, error) {
		if name != "ss" {
			t.Fatalf("unexpected command: %s", name)
		}
		return "", errNotFound
	})

	got, err := tcpStatesLinux(context.Background())
	if err != nil {
		t.Fatalf("tcpStatesLinux: %v", err)
	}
	if got == nil || got.Type != "tcp_states" {
		t.Errorf("expected a tcp_states Details from the /proc/net/tcp fallback, got %+v", got)
	}
	if got.Note != procAttrNote {
		t.Errorf("fallback must carry the per-process-attribution caveat, got %q", got.Note)
	}
}

// TestTCPStatesLinux_SsSucceeds guards the happy path: ss output is parsed
// directly and parseProcNetTCP is never invoked.
func TestTCPStatesLinux_SsSucceeds(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, _ ...string) (string, error) {
		if name != "ss" {
			t.Fatalf("unexpected command: %s", name)
		}
		return "ESTAB 0 0 127.0.0.1:80 127.0.0.1:1234\n", nil
	})

	got, err := tcpStatesLinux(context.Background())
	if err != nil {
		t.Fatalf("tcpStatesLinux: %v", err)
	}
	if got.KV["ESTAB"] != "1" {
		t.Errorf("KV[ESTAB] = %q, want %q (full KV: %+v)", got.KV["ESTAB"], "1", got.KV)
	}
}

// TestParseProcNetTCPAt_MissingFilesSkipped guards the os.Open error branch:
// a netRoot with neither "tcp" nor "tcp6" present (both os.Open calls fail)
// must degrade to an empty-but-valid Details rather than an error.
func TestParseProcNetTCPAt_MissingFilesSkipped(t *testing.T) {
	t.Parallel()
	got, err := parseProcNetTCPAt(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("parseProcNetTCPAt: %v", err)
	}
	if got == nil || len(got.KV) != 0 {
		t.Errorf("expected an empty tcp_states table when both files are missing, got %+v", got)
	}
	if got.Note != procAttrNote {
		t.Errorf("expected the per-process-attribution caveat, got %q", got.Note)
	}
}

// TestParseProcNetTCPAt_ShortLineSkipped guards the len(fields) < 4 skip: a
// malformed/truncated line (e.g. a header or a corrupted row) in tcp/tcp6
// must be ignored rather than panicking on an out-of-range field access, and
// a well-formed row on either file must still be counted.
func TestParseProcNetTCPAt_ShortLineSkipped(t *testing.T) {
	t.Parallel()
	netRoot := t.TempDir()
	// /proc/net/tcp real format: sl local_address rem_address st ...
	// state field (index 3) is hex; 0A = LISTEN, 01 = ESTABLISHED.
	tcpContent := "  sl  local_address rem_address   st\n" + // header: 4 fields, but "st" isn't hex — exercises the ParseInt-error continue too
		"   0: 0100007F:0050 00000000:0000 0A\n" + // well-formed LISTEN, 5 fields (>=4)
		"   1: short\n" // too few fields, must be skipped
	if err := os.WriteFile(filepath.Join(netRoot, "tcp"), []byte(tcpContent), 0644); err != nil {
		t.Fatalf("WriteFile tcp: %v", err)
	}
	tcp6Content := "   0: 00000000000000000000000000000001:1F90 00000000000000000000000000000000:0000 01\n" // ESTABLISHED
	if err := os.WriteFile(filepath.Join(netRoot, "tcp6"), []byte(tcp6Content), 0644); err != nil {
		t.Fatalf("WriteFile tcp6: %v", err)
	}

	got, err := parseProcNetTCPAt(context.Background(), netRoot)
	if err != nil {
		t.Fatalf("parseProcNetTCPAt: %v", err)
	}
	if got.KV["LISTEN"] != "1" {
		t.Errorf("KV[LISTEN] = %q, want %q (full KV: %+v)", got.KV["LISTEN"], "1", got.KV)
	}
	if got.KV["ESTABLISHED"] != "1" {
		t.Errorf("KV[ESTABLISHED] = %q, want %q (full KV: %+v)", got.KV["ESTABLISHED"], "1", got.KV)
	}
}

// tcpStatesMac is only invoked at runtime on darwin, but it's a plain
// function, callable directly on any host — mocking runCmd lets it be
// exercised on Linux CI too. No t.Parallel(): see swapRunCmd's doc comment.
func TestTCPStatesMac(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "netstat" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "Active Internet connections\n" +
			"tcp4       0      0  127.0.0.1.5000    127.0.0.1.54321   ESTABLISHED\n" +
			"tcp4       0      0  *.80              *.*               LISTEN\n" +
			"tcp6       0      0  ::1.5001          ::1.54322         ESTABLISHED\n", nil
	})

	got, err := tcpStatesMac(context.Background())
	if err != nil {
		t.Fatalf("tcpStatesMac: %v", err)
	}
	if got.KV["ESTABLISHED"] != "2" {
		t.Errorf("KV[ESTABLISHED] = %q, want %q (full KV: %+v)", got.KV["ESTABLISHED"], "2", got.KV)
	}
	if got.KV["LISTEN"] != "1" {
		t.Errorf("KV[LISTEN] = %q, want %q (full KV: %+v)", got.KV["LISTEN"], "1", got.KV)
	}
}

// TestTCPStatesMac_RunCmdError guards the error-propagation branch: a failing
// `netstat` invocation must surface the error rather than a partial or empty
// result.
func TestTCPStatesMac_RunCmdError(t *testing.T) {
	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		return "", errNotFound
	})

	_, err := tcpStatesMac(context.Background())
	if err == nil {
		t.Error("expected an error when netstat fails")
	}
}

// TestTCPStatesMac_NonTCPAndShortLinesSkipped guards both the fields[0] !=
// tcp4/tcp6 filter (a udp line must not pollute the TCP state counts) and the
// len(fields) < 6 skip (a truncated line, e.g. a section header) in the same
// pass.
func TestTCPStatesMac_NonTCPAndShortLinesSkipped(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "netstat" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "Active Internet connections\n" +
			"udp4       0      0  *.68              *.*               *\n" + // wrong proto, 6 fields
			"tcp4       0\n" + // too few fields
			"tcp4       0      0  127.0.0.1.5000    127.0.0.1.54321   ESTABLISHED\n", nil
	})

	got, err := tcpStatesMac(context.Background())
	if err != nil {
		t.Fatalf("tcpStatesMac: %v", err)
	}
	if len(got.KV) != 1 || got.KV["ESTABLISHED"] != "1" {
		t.Errorf("expected only the well-formed tcp4 line counted, got %+v", got.KV)
	}
}

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
		// Opening marker present but no closing quote after the name — the
		// before0/ok0 Cut fails.
		{`users:(("nginx`, ""},
		// Name present but no "pid=" field at all — falls back to the bare
		// name (the !ok1 early return).
		{`users:(("nginx"))`, "nginx"},
		// "pid=" present but with no trailing "," or ")" delimiter — pidEnd
		// stays -1 so the raw remainder is used verbatim.
		{`users:(("nginx",pid=999`, "nginx[999]"},
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

// TestTCPStateName guards the /proc/net/tcp hex-state-to-name lookup table,
// including the STATE-N fallback for unrecognised values.
func TestTCPStateName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   int
		want string
	}{
		{1, "ESTABLISHED"},
		{6, "TIME-WAIT"},
		{10, "LISTEN"},
		{11, "CLOSING"},
		{0, "STATE-0"},
		{99, "STATE-99"},
	}
	for _, c := range cases {
		if got := tcpStateName(c.in); got != c.want {
			t.Errorf("tcpStateName(%d) = %q, want %q", c.in, got, c.want)
		}
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

// TestParseSsOutputTimeWaitAttribution guards the TIME-WAIT sibling of the
// CLOSE-WAIT attribution path (same shape, previously untested).
func TestParseSsOutputTimeWaitAttribution(t *testing.T) {
	t.Parallel()
	out := "TIME-WAIT 0 0   127.0.0.1:8080   127.0.0.1:5000   users:((\"curl\",pid=200,fd=3))\n"
	d := parseSsOutput(out, false)
	if len(d.Rows) != 1 || d.Rows[0][0] != "curl[200]" || d.Rows[0][1] != "TIME_WAIT" {
		t.Errorf("expected one TIME_WAIT row for curl[200], got %+v", d.Rows)
	}
	if d.KV["TIME-WAIT"] != "1" {
		t.Errorf("state counts wrong: %+v", d.KV)
	}
}

// TestParseSsOutputEmptyProcSkipped guards that a line with no attributable
// users:(...) field (proc == "") does not pollute the per-process CLOSE_WAIT/
// TIME_WAIT tables.
func TestParseSsOutputEmptyProcSkipped(t *testing.T) {
	t.Parallel()
	out := "CLOSE-WAIT 0 0   127.0.0.1:8080   127.0.0.1:5000\n" +
		"TIME-WAIT  0 0   127.0.0.1:8080   127.0.0.1:5001\n"
	d := parseSsOutput(out, false)
	if len(d.Rows) != 0 {
		t.Errorf("expected no per-process rows without a users:(...) field, got %+v", d.Rows)
	}
	if d.KV["CLOSE-WAIT"] != "1" || d.KV["TIME-WAIT"] != "1" {
		t.Errorf("state counts should still be tallied: %+v", d.KV)
	}
}

// TestParseSsOutputCapsTopFiveEachState guards the "top 5" cap applied
// independently to both the CLOSE_WAIT and TIME_WAIT per-process rankings.
func TestParseSsOutputCapsTopFiveEachState(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for i := range 7 {
		fmt.Fprintf(&b, "CLOSE-WAIT 0 0 127.0.0.1:1 127.0.0.1:2 users:((\"proc%d\",pid=%d,fd=1))\n", i, i)
		fmt.Fprintf(&b, "TIME-WAIT  0 0 127.0.0.1:1 127.0.0.1:2 users:((\"proc%d\",pid=%d,fd=1))\n", i, i)
	}
	d := parseSsOutput(b.String(), false)

	var closeWaitRows, timeWaitRows int
	for _, row := range d.Rows {
		switch row[1] {
		case "CLOSE_WAIT":
			closeWaitRows++
		case "TIME_WAIT":
			timeWaitRows++
		}
	}
	if closeWaitRows != 5 {
		t.Errorf("expected CLOSE_WAIT rows capped at 5, got %d (full rows: %+v)", closeWaitRows, d.Rows)
	}
	if timeWaitRows != 5 {
		t.Errorf("expected TIME_WAIT rows capped at 5, got %d (full rows: %+v)", timeWaitRows, d.Rows)
	}
}
