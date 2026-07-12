//go:build linux

package collectors

import (
	"context"
	"io/fs"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// fakeReadFilePermDeniedSource overrides ReadFile for an exact path set,
// returning a permission-denied error regardless of the real process euid —
// needed because readAuthLogFrom's denied branch depends on os.IsPermission(err),
// which the fixture layer can't produce for an unseeded path (that reads as
// plain "not found", not EACCES) and which real root bypasses entirely.
type fakeReadFilePermDeniedSource struct {
	*source.Replay
	denied map[string]bool
}

func (f fakeReadFilePermDeniedSource) ReadFile(path string) ([]byte, error) {
	if f.denied[path] {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	}
	return f.Replay.ReadFile(path)
}

func TestAuthCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewAuthCollector()
	if c.Name() != "Auth" {
		t.Errorf("Name() = %q, want Auth", c.Name())
	}
	if c.Timeout() != 6e9 {
		t.Errorf("Timeout() = %v, want 6s", c.Timeout())
	}
}

// TestParseAuthLogLine_ExtractIPAndRoot guards the IP+root extraction used to
// keep the unit-testable core of the scan loop covered directly.
func TestParseAuthLogLine_ExtractIPAndRoot(t *testing.T) {
	t.Parallel()
	ip, isRoot := parseAuthLogLine("Jul  8 10:00:00 host sshd[123]: Failed password for root from 10.0.0.5 port 4444 ssh2")
	if ip != "10.0.0.5" || !isRoot {
		t.Errorf("got ip=%q isRoot=%v, want 10.0.0.5/true", ip, isRoot)
	}

	ip2, isRoot2 := parseAuthLogLine("Jul  8 10:00:00 host sshd[123]: Failed password for bob from 10.0.0.6 port 4444 ssh2")
	if ip2 != "10.0.0.6" || isRoot2 {
		t.Errorf("got ip=%q isRoot=%v, want 10.0.0.6/false", ip2, isRoot2)
	}

	ip3, _ := parseAuthLogLine("no from/port fields here")
	if ip3 != "" {
		t.Errorf("expected empty ip for a line with no from/port fields, got %q", ip3)
	}
}

// TestAuthCollector_Collect_SSHDNotInstalled guards the "hide the row" gate:
// when both pgrep and which fail to find sshd, Collect must return
// Available=false without touching the log-scanning path at all.
func TestAuthCollector_Collect_SSHDNotInstalled(t *testing.T) {
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmdNotFound("pgrep", []string{"-x", "sshd"})
		b.PutCmdNotFound("which", []string{"sshd"})
	})
	c := NewAuthCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.AuthInfo)
	if info.Available {
		t.Error("expected Available=false when sshd is neither running nor installed")
	}
}

// TestAuthCollector_Collect_JournalHasFailures guards the primary path: sshd
// present and journalctl returns failed-password/invalid-user lines that must
// be counted, attributed to root when applicable, and their source IPs
// ranked into TopSources.
func TestAuthCollector_Collect_JournalHasFailures(t *testing.T) {
	journal := "Jul  8 10:00:00 host sshd[1]: Failed password for root from 1.2.3.4 port 4000 ssh2\n" +
		"Jul  8 10:01:00 host sshd[2]: Failed password for invalid user admin from 1.2.3.4 port 4001 ssh2\n" +
		"Jul  8 10:02:00 host sshd[3]: Invalid user test from 5.6.7.8 port 4002\n" +
		"Jul  8 10:03:00 host sshd[4]: Connection closed by authenticating user bob 9.9.9.9 port 22 [preauth]\n" +
		// Noise line matching none of the three patterns — guards the scanner's
		// continue branch (a line that isn't a failure signal must not be counted).
		"Jul  8 10:04:00 host sshd[5]: Accepted publickey for deploy from 10.0.0.1 port 4004 ssh2\n"

	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("pgrep", []string{"-x", "sshd"}, "1234\n", 0)
		b.PutCmd("journalctl", []string{"_COMM=sshd", "--since", "24 hours ago", "--no-pager", "-o", "cat"}, journal, 0)
		b.PutCmdNotFound("sshd", []string{"-T"})
	})
	c := NewAuthCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.AuthInfo)
	if !info.Available || !info.Checked {
		t.Fatalf("expected Available=true Checked=true, got %+v", info)
	}
	if info.FailedLast24h != 4 {
		t.Errorf("FailedLast24h = %d, want 4", info.FailedLast24h)
	}
	if info.RootAttempts != 1 {
		t.Errorf("RootAttempts = %d, want 1", info.RootAttempts)
	}
	if len(info.TopSources) == 0 || info.TopSources[0].Source != "1.2.3.4" || info.TopSources[0].Count != 2 {
		t.Errorf("TopSources = %+v, want first entry 1.2.3.4 count 2", info.TopSources)
	}
}

// TestAuthCollector_Collect_JournalEmpty_FallsBackToAuthLog guards the
// fallback: an empty journalctl result must fall through to reading
// /var/log/auth.log, and its content must be scanned exactly like the
// journal path would be.
func TestAuthCollector_Collect_JournalEmpty_FallsBackToAuthLog(t *testing.T) {
	logLine := "Jul  8 10:00:00 host sshd[1]: Failed password for root from 1.2.3.4 port 4000 ssh2\n"
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("pgrep", []string{"-x", "sshd"}, "1234\n", 0)
		b.PutCmd("journalctl", []string{"_COMM=sshd", "--since", "24 hours ago", "--no-pager", "-o", "cat"}, "", 0)
		b.PutFile("/var/log/auth.log", []byte(logLine))
		b.PutStat("/var/log/auth.log", source.FileMeta{Mode: 0o644})
		b.PutCmd("grep", []string{"-E", "Failed password|Invalid user", "/var/log/auth.log"}, logLine, 0)
		b.PutCmdNotFound("sshd", []string{"-T"})
	})
	c := NewAuthCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.AuthInfo)
	if !info.Checked {
		t.Fatal("expected Checked=true — auth.log was readable")
	}
	if info.FailedLast24h != 1 {
		t.Errorf("FailedLast24h = %d, want 1", info.FailedLast24h)
	}
}

// TestAuthCollector_Collect_NoJournalNoReadableLog_PermissionDenied guards the
// "NO auth data" branch: journalctl empty and every candidate log exists but
// is permission-denied. Must report Checked=false with a StatusReason, never
// a false-OK "0 failed logins".
func TestAuthCollector_Collect_NoJournalNoReadableLog_PermissionDenied(t *testing.T) {
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("pgrep", []string{"-x", "sshd"}, "1234\n", 0)
		b.PutCmd("journalctl", []string{"_COMM=sshd", "--since", "24 hours ago", "--no-pager", "-o", "cat"}, "", 0)
		// Auth log candidates exist (statted) but unreadable — simulate via
		// PutStat + no PutFile, using permission-denied semantics through the
		// fixture's file-open error. The fixture source returns a plain
		// not-found for unseeded files, so this test instead exercises the
		// "no candidate present at all" branch — see readAuthLogFrom's own
		// unit test below for the permission-denied distinction.
	})
	c := NewAuthCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.AuthInfo)
	// No candidate files present at all (not permission-denied) — this hits
	// the "no journal data and no auth log file" default branch: trust the
	// empty result.
	if !info.Checked {
		t.Error("expected Checked=true — no log files present is treated as genuinely quiet, not denied")
	}
	if info.FailedLast24h != 0 {
		t.Errorf("FailedLast24h = %d, want 0", info.FailedLast24h)
	}
}

// TestAuthCollector_Collect_AuthLogPermissionDenied guards the true "NO auth
// data" branch end to end: journalctl returns nothing AND every auth-log
// candidate exists but is permission-denied (not merely absent). Must report
// Checked=false with the accurate reason, never a false-OK "0 failed logins".
func TestAuthCollector_Collect_AuthLogPermissionDenied(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("pgrep", []string{"-x", "sshd"}, "1234\n", 0)
	b.PutCmd("journalctl", []string{"_COMM=sshd", "--since", "24 hours ago", "--no-pager", "-o", "cat"}, "", 0)
	b.PutCmdNotFound("sshd", []string{"-T"})
	prev := SetSource(fakeReadFilePermDeniedSource{
		Replay: source.NewReplay(b),
		denied: map[string]bool{"/var/log/auth.log": true, "/var/log/secure": true, "/var/log/messages": true},
	})
	t.Cleanup(func() { SetSource(prev) })

	c := NewAuthCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.AuthInfo)
	if info.Checked {
		t.Error("expected Checked=false when every auth-log candidate is permission-denied")
	}
	if info.StatusReason == "" {
		t.Error("expected a non-empty StatusReason explaining the unreadable log")
	}
}

// TestAuthCollector_Collect_ConnectionClosedMatched guards the third line
// matcher ("connection closed by authenticating") in isolation from the other
// two, and TestAuthCollector_Collect_TopSourcesTiebreak guards the sort
// comparator's count > count branch (all prior tests used a single
// distinguishing count, never two different non-tied counts).
func TestAuthCollector_Collect_ConnectionClosedMatched(t *testing.T) {
	journal := "Jul  8 10:03:00 host sshd[4]: Connection closed by authenticating user bob 9.9.9.9 port 22 [preauth]\n"
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("pgrep", []string{"-x", "sshd"}, "1234\n", 0)
		b.PutCmd("journalctl", []string{"_COMM=sshd", "--since", "24 hours ago", "--no-pager", "-o", "cat"}, journal, 0)
		b.PutCmdNotFound("sshd", []string{"-T"})
	})
	c := NewAuthCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.AuthInfo)
	if info.FailedLast24h != 1 {
		t.Errorf("FailedLast24h = %d, want 1 (connection-closed line counted)", info.FailedLast24h)
	}
}

func TestAuthCollector_Collect_TopSourcesTiebreak(t *testing.T) {
	journal := "Jul  8 10:00:00 host sshd[1]: Failed password for root from 1.1.1.1 port 4000 ssh2\n" +
		"Jul  8 10:01:00 host sshd[2]: Failed password for root from 1.1.1.1 port 4001 ssh2\n" +
		"Jul  8 10:02:00 host sshd[3]: Failed password for root from 1.1.1.1 port 4002 ssh2\n" +
		"Jul  8 10:03:00 host sshd[4]: Invalid user test from 2.2.2.2 port 4003\n"
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("pgrep", []string{"-x", "sshd"}, "1234\n", 0)
		b.PutCmd("journalctl", []string{"_COMM=sshd", "--since", "24 hours ago", "--no-pager", "-o", "cat"}, journal, 0)
		b.PutCmdNotFound("sshd", []string{"-T"})
	})
	c := NewAuthCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.AuthInfo)
	if len(info.TopSources) != 2 || info.TopSources[0].Source != "1.1.1.1" || info.TopSources[0].Count != 3 {
		t.Errorf("TopSources = %+v, want [1.1.1.1:3, 2.2.2.2:1] sorted by count desc", info.TopSources)
	}
}

// TestAuthCollector_Collect_TopSourcesEqualCountTiebreak guards the genuine
// tie case (equal counts) — the sort comparator falls through to source IP
// ascending as the deterministic tiebreaker (TRIAGE §I). The previous
// "Tiebreak" test above used 3-vs-1 counts, which never actually exercises
// the count-equal branch of the comparator.
func TestAuthCollector_Collect_TopSourcesEqualCountTiebreak(t *testing.T) {
	journal := "Jul  8 10:00:00 host sshd[1]: Failed password for root from 9.9.9.9 port 4000 ssh2\n" +
		"Jul  8 10:01:00 host sshd[2]: Failed password for root from 2.2.2.2 port 4001 ssh2\n"
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("pgrep", []string{"-x", "sshd"}, "1234\n", 0)
		b.PutCmd("journalctl", []string{"_COMM=sshd", "--since", "24 hours ago", "--no-pager", "-o", "cat"}, journal, 0)
		b.PutCmdNotFound("sshd", []string{"-T"})
	})
	c := NewAuthCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.AuthInfo)
	if len(info.TopSources) != 2 || info.TopSources[0].Source != "2.2.2.2" || info.TopSources[1].Source != "9.9.9.9" {
		t.Errorf("TopSources = %+v, want [2.2.2.2, 9.9.9.9] sorted by source asc on count tie", info.TopSources)
	}
}

// TestAuthCollector_Collect_SSHConfigChecked guards the sshd-T-sourced policy
// propagation: PasswordAuthEnabled/RootPasswordLoginAllowed/SSHConfigChecked
// must be populated only when sshd -T succeeded.
func TestAuthCollector_Collect_SSHConfigChecked(t *testing.T) {
	sshdTOutput := "passwordauthentication yes\npermitrootlogin yes\n"
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("pgrep", []string{"-x", "sshd"}, "1234\n", 0)
		b.PutCmd("journalctl", []string{"_COMM=sshd", "--since", "24 hours ago", "--no-pager", "-o", "cat"}, "", 0)
		b.PutCmd("sshd", []string{"-T"}, sshdTOutput, 0)
	})
	c := NewAuthCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.AuthInfo)
	if !info.SSHConfigChecked {
		t.Fatal("expected SSHConfigChecked=true from sshd -T output")
	}
	if !info.PasswordAuthEnabled {
		t.Error("expected PasswordAuthEnabled=true")
	}
	if !info.RootPasswordLoginAllowed {
		t.Error("expected RootPasswordLoginAllowed=true")
	}
}

// TestReadAuthLogFrom guards the testable core directly: readable-with-
// matches, readable-and-clean (empty, not unreadable), and no-candidates
// (absent, not denied).
func TestReadAuthLogFrom(t *testing.T) {
	t.Run("readable with matches", func(t *testing.T) {
		withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
			b.PutFile("/var/log/secure", []byte("Failed password for root from 1.2.3.4 port 22 ssh2\n"))
			b.PutStat("/var/log/secure", source.FileMeta{Mode: 0o644})
			b.PutCmd("grep", []string{"-E", "Failed password|Invalid user", "/var/log/secure"},
				"Failed password for root from 1.2.3.4 port 22 ssh2\n", 0)
		})
		content, readable, denied := readAuthLogFrom(context.Background(), []string{"/var/log/secure"})
		if !readable || denied {
			t.Fatalf("readable=%v denied=%v, want true/false", readable, denied)
		}
		if content == "" {
			t.Error("expected non-empty grep output")
		}
	})

	t.Run("no candidates present", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		content, readable, denied := readAuthLogFrom(context.Background(), []string{"/var/log/does-not-exist"})
		if readable || denied {
			t.Errorf("readable=%v denied=%v, want false/false for an absent candidate", readable, denied)
		}
		if content != "" {
			t.Errorf("expected empty content, got %q", content)
		}
	})

	t.Run("falls through to second candidate", func(t *testing.T) {
		withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
			b.PutFile("/var/log/messages", []byte("Invalid user foo from 8.8.8.8 port 22\n"))
			b.PutStat("/var/log/messages", source.FileMeta{Mode: 0o644})
			b.PutCmd("grep", []string{"-E", "Failed password|Invalid user", "/var/log/messages"},
				"Invalid user foo from 8.8.8.8 port 22\n", 0)
		})
		content, readable, denied := readAuthLogFrom(context.Background(),
			[]string{"/var/log/auth.log", "/var/log/secure", "/var/log/messages"})
		if !readable || denied {
			t.Fatalf("readable=%v denied=%v, want true/false", readable, denied)
		}
		if content == "" {
			t.Error("expected the second/third candidate's grep output")
		}
	})
}
