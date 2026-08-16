//go:build linux

package collectors

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// After #749, parseFailedLogins reads failed SSH logins from journald first
// (authoritative, always live) and only falls back to /var/log/secure or
// /var/log/auth.log when journalctl itself is unavailable. Every line — journal
// OR file — passes through the same 1h recency gate, so fixtures must use
// live-relative timestamps (time.Stamp), never fixed calendar dates, or the
// gate silently drops them and the assertions pass/fail on wall-clock luck.

// TestParseFailedLogins_FromAuthLog exercises the FILE fallback (journalctl
// unavailable): a >=3-attempt IP in /var/log/auth.log is flagged, a distinct
// single-attempt "Invalid user" line still counts toward FailedLogins without
// being flagged individually, and a >1h-old line is excluded by the recency
// gate (this is the SSH-specific 1h counter, distinct from the 24h PAM one).
func TestParseFailedLogins_FromAuthLog(t *testing.T) {
	now := time.Now()
	recent := now.Add(-10 * time.Minute).Format(time.Stamp)
	tooOld := now.Add(-2 * time.Hour).Format(time.Stamp)

	lines := []string{
		fmt.Sprintf("%s host sshd[100]: Failed password for invalid user admin from 203.0.113.5 port 40001 ssh2", recent),
		fmt.Sprintf("%s host sshd[101]: Failed password for invalid user admin from 203.0.113.5 port 40002 ssh2", recent),
		fmt.Sprintf("%s host sshd[102]: Failed password for invalid user admin from 203.0.113.5 port 40003 ssh2", recent),
		fmt.Sprintf("%s host sshd[103]: Invalid user test from 198.51.100.9 port 41000", recent),
		fmt.Sprintf("%s host sshd[104]: Failed password for invalid user admin from 203.0.113.5 port 40004 ssh2", tooOld),
	}

	withFixtureSource(t, func(b *source.Bundle) {
		// journalctl unavailable → parseFailedLogins falls back to the file.
		b.PutCmdNotFound("journalctl", []string{"_COMM=sshd", "--since=1 hour ago", "--no-pager", "-q"})
		b.PutFile("/var/log/auth.log", []byte(strings.Join(lines, "\n")+"\n"))
		b.PutStat("/var/log/auth.log", source.FileMeta{Mode: 0o644})
	})

	info := &models.SecurityInfo{}
	parseFailedLogins(context.Background(), info)

	if info.FailedLogins != 4 {
		t.Errorf("expected 4 in-window failed logins (3 from .5 + 1 from .9, excluding the >1h-old line), got %d", info.FailedLogins)
	}
	if len(info.FailedLoginIPs) != 1 || !strings.Contains(info.FailedLoginIPs[0], "203.0.113.5") || !strings.Contains(info.FailedLoginIPs[0], "3 attempts") {
		t.Errorf("expected exactly one flagged IP (203.0.113.5, 3 attempts), got %+v", info.FailedLoginIPs)
	}
}

// TestParseFailedLogins_Clean guards the zero-matches boundary: an auth.log
// present but with no failure lines must leave FailedLogins at zero and
// FailedLoginIPs nil, not a spurious entry.
func TestParseFailedLogins_Clean(t *testing.T) {
	recent := time.Now().Add(-10 * time.Minute).Format(time.Stamp)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("journalctl", []string{"_COMM=sshd", "--since=1 hour ago", "--no-pager", "-q"})
		b.PutFile("/var/log/auth.log", []byte(
			fmt.Sprintf("%s host sshd[1]: Accepted publickey for deploy from 10.0.0.1 port 22 ssh2\n", recent)))
		b.PutStat("/var/log/auth.log", source.FileMeta{Mode: 0o644})
	})
	info := &models.SecurityInfo{}
	parseFailedLogins(context.Background(), info)
	if info.FailedLogins != 0 || len(info.FailedLoginIPs) != 0 {
		t.Errorf("a clean log should leave FailedLogins=0 and FailedLoginIPs empty, got %d / %+v", info.FailedLogins, info.FailedLoginIPs)
	}
}

// TestParseFailedLogins_JournaldPrimary guards that journald is the source of
// record: when journalctl returns output it is parsed directly, without ever
// touching a log file. The exact journalctl args must match what
// parseFailedLogins/authLogSourceLines invoke, or the fixture silently misses
// and the test passes vacuously on the file-fallback branch.
func TestParseFailedLogins_JournaldPrimary(t *testing.T) {
	recent := time.Now().Add(-5 * time.Minute).Format(time.Stamp)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl",
			[]string{"_COMM=sshd", "--since=1 hour ago", "--no-pager", "-q"},
			fmt.Sprintf("%s host sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 40001 ssh2\n", recent),
			0)
	})

	info := &models.SecurityInfo{}
	parseFailedLogins(context.Background(), info)

	if info.FailedLogins != 1 {
		t.Fatalf("expected the journald output to be parsed, got FailedLogins=%d", info.FailedLogins)
	}
}

// TestParseFailedLogins_JournaldLegacyFormat exercises the OpenSSH ≤8 log shape
// through the journald path: three attempts from one IP flag it, a distinct
// single attempt still counts toward the total without being flagged.
func TestParseFailedLogins_JournaldLegacyFormat(t *testing.T) {
	now := time.Now()
	recent := now.Add(-5 * time.Minute).Format(time.Stamp)
	withFixtureSource(t, func(b *source.Bundle) {
		lines := []string{
			fmt.Sprintf("%s host sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 40001 ssh2", recent),
			fmt.Sprintf("%s host sshd[2]: Failed password for invalid user admin from 203.0.113.5 port 40002 ssh2", recent),
			fmt.Sprintf("%s host sshd[3]: Failed password for invalid user admin from 203.0.113.5 port 40003 ssh2", recent),
			fmt.Sprintf("%s host sshd[4]: Failed password for root from 198.51.100.1 port 40004 ssh2", recent),
		}
		b.PutCmd("journalctl", []string{"_COMM=sshd", "--since=1 hour ago", "--no-pager", "-q"}, strings.Join(lines, "\n")+"\n", 0)
	})

	info := &models.SecurityInfo{}
	parseFailedLogins(context.Background(), info)

	if info.FailedLogins != 4 {
		t.Errorf("expected 4 failed logins, got %d", info.FailedLogins)
	}
	if len(info.FailedLoginIPs) != 1 || !strings.Contains(info.FailedLoginIPs[0], "203.0.113.5") {
		t.Errorf("expected exactly one flagged IP (203.0.113.5, 3 attempts), got %+v", info.FailedLoginIPs)
	}
}

// TestParseFailedLogins_JournaldModernFormat exercises the OpenSSH 9+
// "drop connection ... penalty: failed authentication" shape through journald.
func TestParseFailedLogins_JournaldModernFormat(t *testing.T) {
	now := time.Now()
	recent := now.Add(-5 * time.Minute).Format(time.Stamp)
	withFixtureSource(t, func(b *source.Bundle) {
		lines := []string{
			fmt.Sprintf("%s host sshd[1]: drop connection #1 from [203.0.113.7]:40001 on [10.0.0.1]:22 penalty: failed authentication", recent),
			fmt.Sprintf("%s host sshd[2]: drop connection #2 from [203.0.113.7]:40002 on [10.0.0.1]:22 penalty: failed authentication", recent),
			fmt.Sprintf("%s host sshd[3]: drop connection #3 from [203.0.113.7]:40003 on [10.0.0.1]:22 penalty: failed authentication", recent),
		}
		b.PutCmd("journalctl", []string{"_COMM=sshd", "--since=1 hour ago", "--no-pager", "-q"}, strings.Join(lines, "\n")+"\n", 0)
	})

	info := &models.SecurityInfo{}
	parseFailedLogins(context.Background(), info)

	if info.FailedLogins != 3 {
		t.Errorf("expected 3 failed logins, got %d", info.FailedLogins)
	}
	if len(info.FailedLoginIPs) != 1 || !strings.Contains(info.FailedLoginIPs[0], "203.0.113.7") {
		t.Errorf("expected exactly one flagged IP (203.0.113.7, 3 attempts), got %+v", info.FailedLoginIPs)
	}
}

// TestParseFailedLogins_NoSourceUnreadable guards the honest-empty path: with
// journalctl missing AND no readable auth log, parseFailedLogins must set
// FailedLoginsUnreadable (never a silent OK) and leave the counters at zero.
func TestParseFailedLogins_NoSourceUnreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("journalctl", []string{"_COMM=sshd", "--since=1 hour ago", "--no-pager", "-q"})
	})

	info := &models.SecurityInfo{}
	parseFailedLogins(context.Background(), info)

	if !info.FailedLoginsUnreadable {
		t.Error("no journald and no readable file must set FailedLoginsUnreadable")
	}
	if info.FailedLogins != 0 || len(info.FailedLoginIPs) != 0 {
		t.Errorf("expected zero counters when unreadable, got %d / %+v", info.FailedLogins, info.FailedLoginIPs)
	}
}

// TestAuthLogSourceLines_CapsLineCount guards internal-collectors-29-02: the
// flat-file fallback (used when journalctl is unavailable) had no per-line
// limit — only the journalctl branch was bounded, by an unrelated global
// stream-byte cap. This exercises the fallback directly with more lines than
// varLogTailLines (matching the convention logs_linux.go's syslog/messages
// fallback already uses) and asserts the result is capped AND tail-preserving
// (the most recent lines are what a failed-login/PAM scan cares about).
func TestAuthLogSourceLines_CapsLineCount(t *testing.T) {
	total := varLogTailLines + 50
	lines := make([]string, total)
	for i := range lines {
		lines[i] = fmt.Sprintf("line-%04d", i)
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("journalctl", []string{"_COMM=sshd", "--since=1 hour ago", "--no-pager", "-q"})
		b.PutFile("/var/log/auth.log", []byte(strings.Join(lines, "\n")+"\n"))
		b.PutStat("/var/log/auth.log", source.FileMeta{Mode: 0o644})
	})

	got, unreadable := authLogSourceLines(context.Background(), "_COMM=sshd", "--since=1 hour ago", "--no-pager", "-q")
	if unreadable {
		t.Fatal("expected unreadable=false with a readable auth.log")
	}
	if len(got) != varLogTailLines {
		t.Fatalf("len(got) = %d, want exactly the cap %d", len(got), varLogTailLines)
	}
	if got[0] != lines[total-varLogTailLines] || got[len(got)-1] != lines[total-1] {
		t.Errorf("expected the TAIL %d lines preserved, got first=%q last=%q", varLogTailLines, got[0], got[len(got)-1])
	}
}
