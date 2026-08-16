//go:build linux

package collectors

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// Verbatim `iscsiadm -m session -P 1` output (from the live 2-portal LIO rig), with
// the second portal edited to FAILED to exercise failure detection. The old parser
// read the stateless `-m session` form and hardcoded LOGGED_IN, so FailedCount could
// never increment.
const iscsiSessionP1 = `Target: iqn.2026-06.test.dsd:tgt0 (non-flash)
	Current Portal: 192.168.10.69:3260,1
		iSCSI Connection State: LOGGED IN
		iSCSI Session State: LOGGED_IN
		Internal iscsid Session State: NO CHANGE
	Current Portal: 127.0.0.1:3260,1
		iSCSI Connection State: TRANSPORT WAIT
		iSCSI Session State: FAILED
		Internal iscsid Session State: RECONNECT
`

func TestParseISCSISessionsP1(t *testing.T) {
	s := parseISCSISessions(iscsiSessionP1)
	if len(s) != 2 {
		t.Fatalf("got %d sessions, want 2: %+v", len(s), s)
	}
	if s[0].Portal != "192.168.10.69:3260" || strings.ToUpper(s[0].State) != "LOGGED_IN" {
		t.Errorf("session 0 = %+v, want portal 192.168.10.69:3260 LOGGED_IN", s[0])
	}
	if s[1].Portal != "127.0.0.1:3260" || strings.ToUpper(s[1].State) != "FAILED" {
		t.Errorf("session 1 = %+v, want portal 127.0.0.1:3260 FAILED", s[1])
	}
	for _, x := range s {
		if x.Target != "iqn.2026-06.test.dsd:tgt0" {
			t.Errorf("target = %q", x.Target)
		}
	}
	// Failure counting (mirrors Collect): exactly one non-LOGGED_IN session.
	failed := 0
	for _, x := range s {
		if strings.ToUpper(x.State) != "LOGGED_IN" {
			failed++
		}
	}
	if failed != 1 {
		t.Errorf("failed count = %d, want 1", failed)
	}
}

func TestISCSICollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewISCSICollector()
	if c.Name() != "iSCSI" {
		t.Errorf("Name() = %q, want iSCSI", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

// TestISCSICollector_Collect_NotInstalled guards the gate-off path: no
// iscsiadm binary means Collect returns (nil, nil) — absent, not a phantom row.
// lookPath is keyed by the "lookpath/iscsiadm" cache entry, which is simply
// left unseeded here (Cached errors when the key is absent from the bundle).
func TestISCSICollector_Collect_NotInstalled(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {})
	c := NewISCSICollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("expected nil raw when iscsiadm absent, got %+v", raw)
	}
}

// TestISCSICollector_Collect_HappyPath exercises the full path: iscsiadm
// present, `-P 1` succeeds with one LOGGED_IN and one FAILED session.
func TestISCSICollector_Collect_HappyPath(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{"lookpath/iscsiadm": []byte("/usr/bin/iscsiadm")}, nil, func(b *source.Bundle) {
		b.PutCmd("iscsiadm", []string{"-m", "session", "-P", "1"}, iscsiSessionP1, 0)
	})
	c := NewISCSICollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.ISCSIInfo)
	if !ok {
		t.Fatalf("raw type = %T, want *models.ISCSIInfo", raw)
	}
	if !info.Available {
		t.Error("expected Available=true")
	}
	if len(info.Sessions) != 2 {
		t.Fatalf("Sessions = %+v, want 2", info.Sessions)
	}
	if info.FailedCount != 1 {
		t.Errorf("FailedCount = %d, want 1", info.FailedCount)
	}
}

// TestISCSICollector_Collect_NoSessionsAbsent guards the "initiator present
// but zero active sessions" path: -P1 succeeds with empty output → absent
// (nil, nil), matching the open-iscsi-ships-by-default note in Collect.
func TestISCSICollector_Collect_NoSessionsAbsent(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{"lookpath/iscsiadm": []byte("/usr/bin/iscsiadm")}, nil, func(b *source.Bundle) {
		b.PutCmd("iscsiadm", []string{"-m", "session", "-P", "1"}, "", 0)
	})
	c := NewISCSICollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("expected nil raw for zero-session initiator, got %+v", raw)
	}
}

// TestISCSICollector_Collect_FailedNeedsRootSessionsPresent guards the
// unprivileged-but-sessions-exist discriminator: `-P 1` fails (e.g. exit 21,
// same as no-sessions) but /sys/class/iscsi_session/session* is non-empty —
// must report NeedsRoot=true, not silently claim "absent".
func TestISCSICollector_Collect_FailedNeedsRootSessionsPresent(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{"lookpath/iscsiadm": []byte("/usr/bin/iscsiadm")}, nil, func(b *source.Bundle) {
		b.PutCmd("iscsiadm", []string{"-m", "session", "-P", "1"}, "", 21)
		b.PutGlob("/sys/class/iscsi_session/session*", []string{"/sys/class/iscsi_session/session1"})
	})
	c := NewISCSICollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.ISCSIInfo)
	if !ok {
		t.Fatalf("raw type = %T, want *models.ISCSIInfo", raw)
	}
	if !info.Available || !info.NeedsRoot {
		t.Errorf("expected Available=true NeedsRoot=true, got %+v", info)
	}
}

// TestISCSICollector_Collect_FailedNoSessionsAbsent guards the benign case:
// `-P 1` fails AND sysfs shows zero sessions — genuinely absent, not
// needs-root.
func TestISCSICollector_Collect_FailedNoSessionsAbsent(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{"lookpath/iscsiadm": []byte("/usr/bin/iscsiadm")}, nil, func(b *source.Bundle) {
		b.PutCmd("iscsiadm", []string{"-m", "session", "-P", "1"}, "", 21)
		b.PutGlob("/sys/class/iscsi_session/session*", nil)
	})
	c := NewISCSICollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("expected nil raw when iscsiadm fails and no sysfs sessions exist, got %+v", raw)
	}
}

func TestIsISCSIPresent(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{"lookpath/iscsiadm": []byte("/usr/bin/iscsiadm")}, nil, nil)
		if !IsISCSIPresent() {
			t.Error("expected true when iscsiadm is on PATH")
		}
	})

	t.Run("absent", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {}) // lookpath/iscsiadm unseeded
		if IsISCSIPresent() {
			t.Error("expected false when iscsiadm is not installed")
		}
	})
}

func TestISCSISessionDirCount(t *testing.T) {
	t.Run("no sessions", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/sys/class/iscsi_session/session*", nil)
		})
		if got := iscsiSessionDirCount(); got != 0 {
			t.Errorf("iscsiSessionDirCount() = %d, want 0", got)
		}
	})

	t.Run("two sessions", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/sys/class/iscsi_session/session*", []string{
				"/sys/class/iscsi_session/session1",
				"/sys/class/iscsi_session/session2",
			})
		})
		if got := iscsiSessionDirCount(); got != 2 {
			t.Errorf("iscsiSessionDirCount() = %d, want 2", got)
		}
	})
}

// TestParseISCSISessions_UnknownState guards the "Current Portal" with no
// following "iSCSI Session State" line — must flush with state UNKNOWN, not
// drop the session or default it to LOGGED_IN.
func TestParseISCSISessions_UnknownState(t *testing.T) {
	t.Parallel()
	out := "Target: iqn.2026-06.test.dsd:tgt1 (non-flash)\n" +
		"    Current Portal: 10.0.0.9:3260,1\n"
	s := parseISCSISessions(out)
	if len(s) != 1 {
		t.Fatalf("got %d sessions, want 1", len(s))
	}
	if s[0].State != "UNKNOWN" {
		t.Errorf("State = %q, want UNKNOWN", s[0].State)
	}
}

// TestParseISCSISessions_Empty guards the zero-target boundary: empty input
// must yield a nil/empty slice, not panic on the final flush.
func TestParseISCSISessions_Empty(t *testing.T) {
	t.Parallel()
	s := parseISCSISessions("")
	if len(s) != 0 {
		t.Errorf("got %d sessions, want 0 for empty input", len(s))
	}
}

// TestParseISCSISessions_SanitizesControlChars is the regression test for
// internal-collectors-17-06: Target/Portal come straight from iscsiadm's
// output and must have control/ANSI bytes stripped before landing in the
// model.
func TestParseISCSISessions_SanitizesControlChars(t *testing.T) {
	t.Parallel()
	esc := string(rune(27))
	out := "Target: iqn.2026-06.test.dsd:evil" + esc + "[31m (non-flash)\n" +
		"    Current Portal: 10.0.0.9:3260" + esc + "[0m,1\n" +
		"        iSCSI Session State: LOGGED_IN\n"
	s := parseISCSISessions(out)
	if len(s) != 1 {
		t.Fatalf("got %d sessions, want 1", len(s))
	}
	if s[0].Target != "iqn.2026-06.test.dsd:evil[31m" {
		t.Errorf("Target = %q, want ESC stripped", s[0].Target)
	}
	if s[0].Portal != "10.0.0.9:3260[0m" {
		t.Errorf("Portal = %q, want ESC stripped", s[0].Portal)
	}
}
