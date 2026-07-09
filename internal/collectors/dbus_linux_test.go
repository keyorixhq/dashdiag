//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestNewDBusCollectorIdentity guards Name/Timeout wiring.
func TestNewDBusCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewDBusCollector()
	if c == nil {
		t.Fatal("NewDBusCollector() returned nil")
	}
	if c.Name() != "DBus" {
		t.Errorf("Name() = %q, want DBus", c.Name())
	}
	if c.Timeout() != 3*time.Second {
		t.Errorf("Timeout() = %v, want 3s", c.Timeout())
	}
}

// TestDBusCollector_Collect_NonSystemdHost guards the gate-off path: on a
// non-systemd host (no /run/systemd/{private,system}), Collect must return
// (nil, nil) rather than a phantom "D-Bus failed" CRIT.
func TestDBusCollector_Collect_NonSystemdHost(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // systemdPresentViaSource() -> false

	c := NewDBusCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("expected nil result on non-systemd host, got %+v", raw)
	}
}

// TestDBusCollector_Collect_Active guards the healthy path: dbus resolves as
// active and no journal lookup is needed (LastError stays empty).
func TestDBusCollector_Collect_Active(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/run/systemd/system", source.FileMeta{})
		b.PutCmd("systemctl", []string{"is-active", "dbus"}, "active\n", 0)
	})

	c := NewDBusCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.DBusInfo)
	if !ok {
		t.Fatalf("unexpected type %T", raw)
	}
	if !info.Available {
		t.Error("expected Available=true on a systemd host")
	}
	if !info.Active || info.Status != "active" {
		t.Errorf("expected Active=true Status=active, got %+v", info)
	}
	if info.LastError != "" {
		t.Errorf("expected no LastError on active bus, got %q", info.LastError)
	}
}

// TestDBusCollector_Collect_FailedPullsLastError guards the confirmed-down
// path: a "failed" status must trigger a journal lookup for the last error.
func TestDBusCollector_Collect_FailedPullsLastError(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/run/systemd/system", source.FileMeta{})
		b.PutCmd("systemctl", []string{"is-active", "dbus"}, "failed\n", 3)
		b.PutCmd("journalctl", []string{
			"-u", "dbus.service", "-p", "err", "-n", "5", "--no-pager", "-o", "cat",
		}, "Failed to activate service 'org.freedesktop.NetworkManager'\n", 0)
	})

	c := NewDBusCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.DBusInfo)
	if info.Active {
		t.Error("expected Active=false when status is failed")
	}
	if info.Status != "failed" {
		t.Errorf("Status = %q, want failed", info.Status)
	}
	if info.LastError != "Failed to activate service 'org.freedesktop.NetworkManager'" {
		t.Errorf("LastError = %q, unexpected", info.LastError)
	}
}

// TestDBusCollector_Collect_InactiveNoJournalNoise guards the same
// journal-pull branch for "inactive", but with the journal returning nothing
// useful — LastError should stay empty, not error the collector.
func TestDBusCollector_Collect_InactiveNoJournalNoise(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/run/systemd/system", source.FileMeta{})
		b.PutCmd("systemctl", []string{"is-active", "dbus"}, "inactive\n", 3)
		b.PutCmdNotFound("journalctl", []string{
			"-u", "dbus.service", "-p", "err", "-n", "5", "--no-pager", "-o", "cat",
		})
	})

	c := NewDBusCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.DBusInfo)
	if info.Status != "inactive" || info.Active {
		t.Errorf("expected Status=inactive Active=false, got %+v", info)
	}
	if info.LastError != "" {
		t.Errorf("expected empty LastError when journalctl is unavailable, got %q", info.LastError)
	}
}

// TestDBusCollector_Collect_UnknownStatusSkipsJournal guards the "unknown"
// sentinel: empty systemctl output must NOT be treated as failed, and must
// NOT trigger a journal lookup (whose last line is usually a benign success
// message that must not masquerade as an error).
func TestDBusCollector_Collect_UnknownStatusSkipsJournal(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/run/systemd/system", source.FileMeta{})
		b.PutCmd("systemctl", []string{"is-active", "dbus"}, "", 3)
		// journalctl deliberately NOT seeded — if Collect calls it, the test
		// fails via ErrNotRecorded surfacing as ineffective LastError read
		// (still returns "" so we assert Status/Active instead, but the
		// absence of a seed also documents the branch must not need it).
	})

	c := NewDBusCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.DBusInfo)
	if info.Status != "unknown" {
		t.Errorf("Status = %q, want unknown", info.Status)
	}
	if info.Active {
		t.Error("expected Active=false for unknown status")
	}
	if info.LastError != "" {
		t.Errorf("expected empty LastError on unknown status (journal must not be consulted), got %q", info.LastError)
	}
}

// TestCollectDBusLastError guards the priority-filtered journal parser
// directly: multiple lines, blank lines, and the reverse-scan for the last
// non-empty line.
func TestCollectDBusLastError(t *testing.T) {
	t.Run("returns last non-empty line", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("journalctl", []string{
				"-u", "dbus.service", "-p", "err", "-n", "5", "--no-pager", "-o", "cat",
			}, "first error\nsecond error\n\n", 0)
		})
		got := collectDBusLastError(context.Background())
		if got != "second error" {
			t.Errorf("got %q, want %q", got, "second error")
		}
	})

	t.Run("command failure returns empty", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmdNotFound("journalctl", []string{
				"-u", "dbus.service", "-p", "err", "-n", "5", "--no-pager", "-o", "cat",
			})
		})
		if got := collectDBusLastError(context.Background()); got != "" {
			t.Errorf("got %q, want empty on command failure", got)
		}
	})

	t.Run("empty output returns empty", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("journalctl", []string{
				"-u", "dbus.service", "-p", "err", "-n", "5", "--no-pager", "-o", "cat",
			}, "", 0)
		})
		if got := collectDBusLastError(context.Background()); got != "" {
			t.Errorf("got %q, want empty on empty output", got)
		}
	})

	t.Run("only blank lines returns empty", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("journalctl", []string{
				"-u", "dbus.service", "-p", "err", "-n", "5", "--no-pager", "-o", "cat",
			}, "   \n\n  \n", 0)
		})
		if got := collectDBusLastError(context.Background()); got != "" {
			t.Errorf("got %q, want empty when all lines are blank", got)
		}
	})
}
