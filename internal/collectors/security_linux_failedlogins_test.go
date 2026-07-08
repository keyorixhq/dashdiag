//go:build linux

package collectors

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestParseFailedLogins_FromAuthLog guards the 1h SSH brute-force counter read
// from /var/log/auth.log: a >=3-attempt IP must be flagged in FailedLoginIPs,
// a distinct single-attempt "Invalid user" line must still count toward
// FailedLogins without being flagged individually, and a >1h-old line must be
// excluded by the recency gate (distinct from the 24h PAM-failure counter —
// this is the older, SSH-specific counter).
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
		b.PutFile("/var/log/auth.log", []byte(strings.Join(lines, "\n")+"\n"))
		b.PutStat("/var/log/auth.log", source.FileMeta{Mode: 0o644})
	})

	info := &models.SecurityInfo{}
	parseFailedLogins(info)

	if info.FailedLogins != 4 {
		t.Errorf("expected 4 in-window failed logins (3 from .5 + 1 from .9, excluding the >1h-old line), got %d", info.FailedLogins)
	}
	if len(info.FailedLoginIPs) != 1 || !strings.Contains(info.FailedLoginIPs[0], "203.0.113.5") || !strings.Contains(info.FailedLoginIPs[0], "3 attempts") {
		t.Errorf("expected exactly one flagged IP (203.0.113.5, 3 attempts), got %+v", info.FailedLoginIPs)
	}
}

// TestParseFailedLogins_Clean guards the zero-matches boundary: an auth.log
// present but with no matching failure lines must leave FailedLogins at zero
// and FailedLoginIPs nil, not a spurious entry.
func TestParseFailedLogins_Clean(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/log/auth.log", []byte("Jul  8 10:00:01 host sshd[1]: Accepted publickey for deploy from 10.0.0.1 port 22 ssh2\n"))
		b.PutStat("/var/log/auth.log", source.FileMeta{Mode: 0o644})
	})
	info := &models.SecurityInfo{}
	parseFailedLogins(info)
	if info.FailedLogins != 0 || len(info.FailedLoginIPs) != 0 {
		t.Errorf("a clean log should leave FailedLogins=0 and FailedLoginIPs empty, got %d / %+v", info.FailedLogins, info.FailedLoginIPs)
	}
}

// TestParseFailedLogins_NoLogFiles_FallsBackToJournal guards the journald-only
// fallback path (Debian 13+, neither /var/log/secure nor /var/log/auth.log
// present): the exact journalctl args must match what parseFailedLogins /
// parseFailedLoginsFromJournal actually invokes, or the fixture silently
// misses and the test passes vacuously on the "err != nil -> return" branch.
func TestParseFailedLogins_NoLogFiles_FallsBackToJournal(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl",
			[]string{"_COMM=sshd", "--since=1 hour ago", "--no-pager", "-q"},
			"Jul 08 10:00:01 host sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 40001 ssh2\n",
			0)
	})

	info := &models.SecurityInfo{}
	parseFailedLogins(info)

	if info.FailedLogins != 1 {
		t.Fatalf("expected the journalctl fallback to be parsed, got FailedLogins=%d", info.FailedLogins)
	}
}

// TestParseFailedLoginsFromJournal_LegacyFormat exercises the OpenSSH <=8
// log shape directly (not through the auth.log-absent dispatcher).
func TestParseFailedLoginsFromJournal_LegacyFormat(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		lines := []string{
			"Jul 08 10:00:01 host sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 40001 ssh2",
			"Jul 08 10:00:02 host sshd[2]: Failed password for invalid user admin from 203.0.113.5 port 40002 ssh2",
			"Jul 08 10:00:03 host sshd[3]: Failed password for invalid user admin from 203.0.113.5 port 40003 ssh2",
			"Jul 08 10:00:04 host sshd[4]: Failed password for root from 198.51.100.1 port 40004 ssh2",
		}
		b.PutCmd("journalctl", []string{"_COMM=sshd", "--since=1 hour ago", "--no-pager", "-q"}, strings.Join(lines, "\n")+"\n", 0)
	})

	info := &models.SecurityInfo{}
	parseFailedLoginsFromJournal(info)

	if info.FailedLogins != 4 {
		t.Errorf("expected 4 failed logins, got %d", info.FailedLogins)
	}
	if len(info.FailedLoginIPs) != 1 || !strings.Contains(info.FailedLoginIPs[0], "203.0.113.5") {
		t.Errorf("expected exactly one flagged IP (203.0.113.5, 3 attempts), got %+v", info.FailedLoginIPs)
	}
}

// TestParseFailedLoginsFromJournal_ModernFormat exercises the OpenSSH 9+
// "drop connection ... penalty: failed authentication" shape.
func TestParseFailedLoginsFromJournal_ModernFormat(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		lines := []string{
			"Jul 08 10:00:01 host sshd[1]: drop connection #1 from [203.0.113.7]:40001 on [10.0.0.1]:22 penalty: failed authentication",
			"Jul 08 10:00:02 host sshd[2]: drop connection #2 from [203.0.113.7]:40002 on [10.0.0.1]:22 penalty: failed authentication",
			"Jul 08 10:00:03 host sshd[3]: drop connection #3 from [203.0.113.7]:40003 on [10.0.0.1]:22 penalty: failed authentication",
		}
		b.PutCmd("journalctl", []string{"_COMM=sshd", "--since=1 hour ago", "--no-pager", "-q"}, strings.Join(lines, "\n")+"\n", 0)
	})

	info := &models.SecurityInfo{}
	parseFailedLoginsFromJournal(info)

	if info.FailedLogins != 3 {
		t.Errorf("expected 3 failed logins, got %d", info.FailedLogins)
	}
	if len(info.FailedLoginIPs) != 1 || !strings.Contains(info.FailedLoginIPs[0], "203.0.113.7") {
		t.Errorf("expected exactly one flagged IP (203.0.113.7, 3 attempts), got %+v", info.FailedLoginIPs)
	}
}

// TestParseFailedLoginsFromJournal_CommandUnavailable guards the honest-empty
// path: journalctl missing entirely must leave FailedLogins at zero rather
// than panicking or misreporting.
func TestParseFailedLoginsFromJournal_CommandUnavailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("journalctl", []string{"_COMM=sshd", "--since=1 hour ago", "--no-pager", "-q"})
	})

	info := &models.SecurityInfo{}
	parseFailedLoginsFromJournal(info)

	if info.FailedLogins != 0 || len(info.FailedLoginIPs) != 0 {
		t.Errorf("expected no failed logins when journalctl is unavailable, got %d / %+v", info.FailedLogins, info.FailedLoginIPs)
	}
}
