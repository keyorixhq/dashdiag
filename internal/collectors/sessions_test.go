//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestSessionsCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewSessionsCollector()
	if c.Name() != "Sessions" {
		t.Errorf("Name() = %q, want Sessions", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

// TestSessionsCollector_Collect_WNotFound guards the "w not available" path:
// Collect must return an empty (non-nil) SessionsInfo, not an error.
func TestSessionsCollector_Collect_WNotFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("w", []string{"-h"})
	})
	c := NewSessionsCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.SessionsInfo)
	if !ok {
		t.Fatalf("raw type = %T, want *models.SessionsInfo", raw)
	}
	if info.TotalCount != 0 || len(info.Sessions) != 0 {
		t.Errorf("expected empty SessionsInfo when w is absent, got %+v", info)
	}
}

// TestSessionsCollector_Collect_HappyPath exercises the full path: `w -h`
// succeeds with a mix of local and remote sessions, and IsPVE is derived from
// the pvedaemon binary presence.
func TestSessionsCollector_Collect_HappyPath(t *testing.T) {
	wOut := "andrei pts/0    192.168.1.1      10:00    0.00s 0.01s  0.00s w -h\n" +
		"root   tty1                      09:00   55:12  0.02s  0.00s -bash\n"
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("w", []string{"-h"}, wOut, 0)
		b.PutStat("/usr/bin/pvedaemon", source.FileMeta{Mode: 0o755})
	})
	c := NewSessionsCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.SessionsInfo)
	if info.TotalCount != 2 {
		t.Fatalf("TotalCount = %d, want 2", info.TotalCount)
	}
	if info.RemoteCount != 1 {
		t.Errorf("RemoteCount = %d, want 1", info.RemoteCount)
	}
	if !info.IsPVE {
		t.Error("expected IsPVE=true when /usr/bin/pvedaemon exists")
	}
}

// TestSessionsCollector_Collect_NotPVE guards IsPVE staying false absent the
// pvedaemon binary.
func TestSessionsCollector_Collect_NotPVE(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("w", []string{"-h"}, "root tty1 09:00 0.00s 0.01s 0.00s -bash\n", 0)
	})
	c := NewSessionsCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.SessionsInfo)
	if info.IsPVE {
		t.Error("expected IsPVE=false when pvedaemon is absent")
	}
}

// TestParseSessions_LocalConsole guards the classic local-login shape: TTY
// present, FROM column blank (collapsed by strings.Fields).
func TestParseSessions_LocalConsole(t *testing.T) {
	t.Parallel()
	out := "root   tty1                      09:00   55:12  0.02s  0.00s -bash\n"
	info := parseSessions(out)
	if len(info.Sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(info.Sessions))
	}
	s := info.Sessions[0]
	if s.User != "root" || s.TTY != "tty1" || s.From != "" {
		t.Errorf("session = %+v, want local console (no From)", s)
	}
	if info.RemoteCount != 0 {
		t.Errorf("RemoteCount = %d, want 0 for local console", info.RemoteCount)
	}
	if info.RootSSH {
		t.Error("RootSSH should be false for a local console root login")
	}
}

// TestParseSessions_RemoteWithFrom guards the TTY+FROM+remote-IP shape and
// RootSSH/RemoteCount/UniqueIPs derivation.
func TestParseSessions_RemoteWithFrom(t *testing.T) {
	t.Parallel()
	out := "root   pts/0    192.168.1.50      10:00    0.00s 0.01s  0.00s -bash\n"
	info := parseSessions(out)
	if len(info.Sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(info.Sessions))
	}
	s := info.Sessions[0]
	if s.From != "192.168.1.50" {
		t.Errorf("From = %q, want 192.168.1.50", s.From)
	}
	if info.RemoteCount != 1 {
		t.Errorf("RemoteCount = %d, want 1", info.RemoteCount)
	}
	if !info.RootSSH {
		t.Error("expected RootSSH=true for root logged in with a From host")
	}
	if len(info.UniqueIPs) != 1 || info.UniqueIPs[0] != "192.168.1.50" {
		t.Errorf("UniqueIPs = %v, want [192.168.1.50]", info.UniqueIPs)
	}
}

// TestParseSessions_PTYLessRemote guards the pty-less session shape: TTY
// column blank, fields[1] is the FROM host directly.
func TestParseSessions_PTYLessRemote(t *testing.T) {
	t.Parallel()
	out := "eve 10.0.0.9 10:00 0.00s 0.01s 0.00s ssh host cmd\n"
	info := parseSessions(out)
	if len(info.Sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(info.Sessions))
	}
	s := info.Sessions[0]
	if s.TTY != "" || s.From != "10.0.0.9" {
		t.Errorf("session = %+v, want TTY blank, From=10.0.0.9", s)
	}
	if info.RemoteCount != 1 {
		t.Errorf("RemoteCount = %d, want 1", info.RemoteCount)
	}
}

// TestParseSessions_DashFrom guards the "-" FROM marker (present-but-local
// column, not a column-shift signal) and confirms it does NOT count as remote.
func TestParseSessions_DashFrom(t *testing.T) {
	t.Parallel()
	out := "andrei pts/1 - 10:00 0.00s 0.01s 0.00s -zsh\n"
	info := parseSessions(out)
	if len(info.Sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(info.Sessions))
	}
	s := info.Sessions[0]
	if s.From != "-" {
		t.Errorf("From = %q, want -", s.From)
	}
	if info.RemoteCount != 0 {
		t.Errorf("RemoteCount = %d, want 0 for From=-", info.RemoteCount)
	}
}

// TestParseSessions_UnrecognisedColumn guards the default fallback branch:
// a fields[1] value that is neither a TTY name nor host-like (isTTYName=false,
// looksLikeHost=false — an all-digit, dotless, non-timestamp token) is treated
// as the TTY, matching the "prior behaviour" fallback comment in parseSessions.
func TestParseSessions_UnrecognisedColumn(t *testing.T) {
	t.Parallel()
	out := "bob 12345 10:00 0.00s 0.01s 0.00s cmd\n"
	info := parseSessions(out)
	if len(info.Sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(info.Sessions))
	}
	if info.Sessions[0].TTY != "12345" {
		t.Errorf("TTY = %q, want 12345 (fallback branch)", info.Sessions[0].TTY)
	}
}

// TestParseSessions_LongIdleAndCommand guards the >8h idle flag and the
// Command field join for WHAT columns beyond index 4. IDLE "9:00m" is the `w`
// HH:MMm form (hours:minutes, w's format once idle exceeds 1h) = 9h = 32400s.
func TestParseSessions_LongIdleAndCommand(t *testing.T) {
	t.Parallel()
	out := "andrei pts/0 10.0.0.1 09:00 9:00m 0.01s 0.00s vim somefile.go\n"
	info := parseSessions(out)
	if len(info.Sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(info.Sessions))
	}
	s := info.Sessions[0]
	if s.Command != "vim somefile.go" {
		t.Errorf("Command = %q, want %q", s.Command, "vim somefile.go")
	}
	if len(info.LongIdle) != 1 || info.LongIdle[0] != "andrei" {
		t.Errorf("LongIdle = %v, want [andrei] (idle > 8h)", info.LongIdle)
	}
}

// TestParseSessions_ShortLineSkipped guards the < 4 field minimum-length gate
// and blank-line skip.
func TestParseSessions_ShortLineSkipped(t *testing.T) {
	t.Parallel()
	out := "\n   \nbob tty1 x\n"
	info := parseSessions(out)
	if len(info.Sessions) != 0 {
		t.Errorf("got %d sessions, want 0 (all lines too short/blank)", len(info.Sessions))
	}
}

// TestParseSessions_UniqueIPsDedup guards that two sessions from the same
// remote IP (with different ports) collapse into ONE UniqueIPs entry via
// net.SplitHostPort.
func TestParseSessions_UniqueIPsDedup(t *testing.T) {
	t.Parallel()
	out := "a pts/0 10.0.0.5:2222 09:00 0.00s 0.01s 0.00s bash\n" +
		"b pts/1 10.0.0.5:2223 09:01 0.00s 0.01s 0.00s bash\n"
	info := parseSessions(out)
	if info.RemoteCount != 2 {
		t.Fatalf("RemoteCount = %d, want 2", info.RemoteCount)
	}
	if len(info.UniqueIPs) != 1 || info.UniqueIPs[0] != "10.0.0.5" {
		t.Errorf("UniqueIPs = %v, want [10.0.0.5] deduped", info.UniqueIPs)
	}
}

func TestIsTTYName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want bool
	}{
		{"tty1", true},
		{"ttyS0", true},
		{"pts/0", true},
		{"console", true},
		{"ttys000", true},
		{":0", true},
		{":0.0", true},
		{"192.168.1.1", false},
		{"", false},
		{":", false},
		{":a", false},
	}
	for _, tt := range tests {
		if got := isTTYName(tt.in); got != tt.want {
			t.Errorf("isTTYName(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// looksLikeHost is already covered by TestLooksLikeHost in
// parser_hardening_test.go — not duplicated here.

// TestLooksLikeHost_NarrowedDayDateExclusion is the regression test for the
// internal-collectors-30-02 residual: wDayLogin/wDateLogin used to be
// case-insensitive / any-3-letters, so a real (if unusual) short hostname
// exactly shaped like a `w` LOGIN@ day-name or date-stamp string was
// misclassified as "not a host" — silently losing RemoteCount/RootSSH
// attribution. Since dsd forces LC_ALL=C/LANG=C on every subprocess
// (source.HardenedEnv), `w`'s real LOGIN@ output is always exact C-locale
// title case ("Mon", "Jun") — never lowercase/uppercase, and never an
// arbitrary 3-letter sequence — so anchoring the patterns to that exact
// shape is real corroboration, not a guess.
func TestLooksLikeHost_NarrowedDayDateExclusion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		// A lowercase or uppercase day-name-shaped hostname is no longer
		// swallowed by the (now case-sensitive) day-name exclusion.
		{"sun", true},
		{"mon", true},
		{"MON", true},
		// The genuine `w` LOGIN@ shape (exact C-locale title case) is still
		// excluded — the narrowing must not regress the original fix.
		{"Mon", false},
		{"Tue08", false},
		// A dotless string shaped like "NN<3 letters>NN" that is NOT a real
		// month abbreviation is no longer swallowed by the old
		// any-3-letters date pattern.
		{"23xyz24", true},
		{"77abc11", true},
		// The genuine `w` LOGIN@ date shape (real month abbreviation, exact
		// C-locale title case) is still excluded.
		{"23Jun24", false},
		{"01Dec99", false},
	}
	for _, tc := range cases {
		if got := looksLikeHost(tc.in); got != tc.want {
			t.Errorf("looksLikeHost(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseIdleSec(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"?", 0},
		{"0.00s", 0},
		{"45s", 45},
		{"2days", 172800},
		{"1:00m", 3600},
		{"1:30m", 5400},
		{"45m", 2700}, // "m" suffix with no ":" — bare minutes
		{"3:12", 192},
		{"garbage", 0},
	}
	for _, tt := range tests {
		if got := parseIdleSec(tt.in); got != tt.want {
			t.Errorf("parseIdleSec(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestAtoi(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want int
	}{
		{"123", 123},
		{"", 0},
		{"12a3", 123}, // non-digits skipped
	}
	for _, tt := range tests {
		if got := atoi(tt.in); got != tt.want {
			t.Errorf("atoi(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestParseFloatSimple(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want float64
	}{
		{"0.00", 0},
		{"45", 45},
		{"1.5", 1.5},
		{"-1.5", -1.5},
		{"0.5", 0.5},
	}
	for _, tt := range tests {
		if got := parseFloatSimple(tt.in); got != tt.want {
			t.Errorf("parseFloatSimple(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestIsAllDigits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"123", true},
		{"12a", false},
		{"0", true},
	}
	for _, tt := range tests {
		if got := isAllDigits(tt.in); got != tt.want {
			t.Errorf("isAllDigits(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
