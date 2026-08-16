//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestNewAuditCollectorIdentity guards Name/Timeout wiring.
func TestNewAuditCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewAuditCollector()
	if c == nil {
		t.Fatal("NewAuditCollector() returned nil")
	}
	if c.Name() != "Auditd" {
		t.Errorf("Name() = %q, want Auditd", c.Name())
	}
	if c.Timeout() != 4*time.Second {
		t.Errorf("Timeout() = %v, want 4s", c.Timeout())
	}
}

// TestAuditCollector_Collect_NotInstalled guards the gate-off path: no
// auditctl binary means an empty AuditInfo{} (Available=false), no further
// commands run.
func TestAuditCollector_Collect_NotInstalled(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{}, nil, nil) // lookpath/auditctl absent

	c := NewAuditCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.AuditInfo)
	if info.Available {
		t.Errorf("expected Available=false, got %+v", info)
	}
}

// TestAuditCollector_Collect_RunningViaSystemctl guards the systemd
// is-active=running path plus rule count and event count parsing.
func TestAuditCollector_Collect_RunningViaSystemctl(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/auditctl": []byte("/sbin/auditctl"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "auditd"}, "active\n", 0)
		b.PutCmd("auditctl", []string{"-l"}, "-w /etc/passwd -p wa -k passwd_changes\n-w /etc/shadow -p wa -k shadow_changes\n", 0)
		b.PutStat("/var/log/audit/audit.log", source.FileMeta{Size: 2147483648}) // 2 GiB
		b.PutCmd("ausearch", []string{"-ts", "1hour ago", "--raw"}, "type=SYSCALL msg=audit(...)\ntype=CWD msg=audit(...)\n", 0)
	})

	c := NewAuditCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.AuditInfo)
	if !info.Available {
		t.Fatal("expected Available=true")
	}
	if !info.Running {
		t.Error("expected Running=true via systemctl is-active")
	}
	if info.RulesLoaded != 2 {
		t.Errorf("RulesLoaded = %d, want 2", info.RulesLoaded)
	}
	if info.RulesUnreadable {
		t.Error("expected RulesUnreadable=false when auditctl -l succeeds")
	}
	if info.AuditLogSizeUnreadable {
		t.Error("expected AuditLogSizeUnreadable=false when stat succeeds")
	}
	wantGB := float64(2147483648) / (1024 * 1024 * 1024)
	if info.AuditLogSizeGB != wantGB {
		t.Errorf("AuditLogSizeGB = %v, want %v", info.AuditLogSizeGB, wantGB)
	}
	if info.EventsLast1h != 2 {
		t.Errorf("EventsLast1h = %d, want 2", info.EventsLast1h)
	}
	if info.EventsUnreadable {
		t.Error("expected EventsUnreadable=false when ausearch succeeds")
	}
}

// TestAuditCollector_Collect_RunningViaProcessFallback guards the
// non-systemd-host fallback: systemctl fails but /proc/<pid>/comm matches
// "auditd" — Running must still be true (portable across OpenRC/SysV hosts).
func TestAuditCollector_Collect_RunningViaProcessFallback(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/auditctl": []byte("/sbin/auditctl"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "auditd"}, "", 1) // fails (no systemd)
		b.PutDir("/proc", []string{"1", "42", "self"})
		b.PutFile("/proc/1/comm", []byte("init\n"))
		b.PutFile("/proc/42/comm", []byte("auditd\n"))
		b.PutCmd("auditctl", []string{"-l"}, "", 1) // rule list unreadable — no rules counted
		// audit log stat deliberately not seeded -> AuditLogSizeUnreadable
		b.PutCmd("ausearch", []string{"-ts", "1hour ago", "--raw"}, "", 1) // ausearch fails
	})

	c := NewAuditCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.AuditInfo)
	if !info.Running {
		t.Error("expected Running=true via /proc/<pid>/comm fallback")
	}
	if info.RulesLoaded != 0 {
		t.Errorf("RulesLoaded = %d, want 0 (auditctl -l failed)", info.RulesLoaded)
	}
	// internal-collectors-01-03: a failed auditctl -l/ausearch must set an
	// explicit sentinel, not just leave the counts at zero — otherwise a
	// non-root run against a host with real rules/events is indistinguishable
	// from a genuinely unconfigured auditd.
	if !info.RulesUnreadable {
		t.Error("expected RulesUnreadable=true when auditctl -l fails")
	}
	if !info.AuditLogSizeUnreadable {
		t.Error("expected AuditLogSizeUnreadable=true when the audit log can't be stat'd")
	}
	if info.EventsLast1h != 0 {
		t.Errorf("EventsLast1h = %d, want 0 (ausearch failed)", info.EventsLast1h)
	}
	if !info.EventsUnreadable {
		t.Error("expected EventsUnreadable=true when ausearch fails")
	}
}

// TestAuditCollector_Collect_NotRunning guards the fully-stopped path: neither
// systemctl nor the process table shows auditd running.
func TestAuditCollector_Collect_NotRunning(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/auditctl": []byte("/sbin/auditctl"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "auditd"}, "inactive\n", 3)
		b.PutDir("/proc", []string{"1"})
		b.PutFile("/proc/1/comm", []byte("init\n"))
		b.PutCmd("auditctl", []string{"-l"}, "", 1)
		b.PutCmd("ausearch", []string{"-ts", "1hour ago", "--raw"}, "", 1)
	})

	c := NewAuditCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.AuditInfo)
	if info.Running {
		t.Error("expected Running=false when neither systemctl nor process table shows auditd")
	}
}

// TestAuditCollector_Collect_SpoofedCommNotTrusted is the regression test for
// internal-collectors-01-04: a process that renamed itself "auditd" via
// prctl(PR_SET_NAME) (matched by comm alone, the pre-fix behaviour) but whose
// real /proc/<pid>/exe resolves OUTSIDE any genuine system-binary directory
// must NOT suppress the "auditd not running" compliance signal.
func TestAuditCollector_Collect_SpoofedCommNotTrusted(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/auditctl": []byte("/sbin/auditctl"),
	}, map[string]string{
		"/proc/42/exe": "/home/attacker/auditd", // spoofed: comm claims auditd, exe does not
	}, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "auditd"}, "", 1) // fails (no systemd)
		b.PutDir("/proc", []string{"1", "42"})
		b.PutFile("/proc/1/comm", []byte("init\n"))
		b.PutFile("/proc/42/comm", []byte("auditd\n")) // spoofed comm
		b.PutCmd("auditctl", []string{"-l"}, "", 1)
		b.PutCmd("ausearch", []string{"-ts", "1hour ago", "--raw"}, "", 1)
	})

	c := NewAuditCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.AuditInfo)
	if info.Running {
		t.Error("expected Running=false — a spoofed comm name whose real exe is outside a system dir must not suppress the compliance WARN")
	}
}

// TestVerifiedAuditdRunning covers the standalone helper directly, including
// the exe-unreadable fallback (the collector's pre-fix posture: still trust
// a comm-only match when verification is genuinely impossible).
func TestVerifiedAuditdRunning(t *testing.T) {
	t.Run("verified via system-dir exe", func(t *testing.T) {
		withCombinedFixture(t, nil, map[string]string{
			"/proc/42/exe": "/sbin/auditd",
		}, func(b *source.Bundle) {
			b.PutDir("/proc", []string{"1", "42"})
			b.PutFile("/proc/1/comm", []byte("init\n"))
			b.PutFile("/proc/42/comm", []byte("auditd\n"))
		})
		if !verifiedAuditdRunning("/proc") {
			t.Error("expected true — comm and exe both match a genuine auditd")
		}
	})

	t.Run("spoofed comm with real exe outside system dir", func(t *testing.T) {
		withCombinedFixture(t, nil, map[string]string{
			"/proc/42/exe": "/tmp/evil-payload",
		}, func(b *source.Bundle) {
			b.PutDir("/proc", []string{"42"})
			b.PutFile("/proc/42/comm", []byte("auditd\n"))
		})
		if verifiedAuditdRunning("/proc") {
			t.Error("expected false — exe resolved and is not under a system-binary dir")
		}
	})

	t.Run("exe unreadable falls back to comm-only trust", func(t *testing.T) {
		withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
			b.PutDir("/proc", []string{"42"})
			b.PutFile("/proc/42/comm", []byte("auditd\n"))
			// /proc/42/exe deliberately not seeded -> Readlink returns an error.
		})
		if !verifiedAuditdRunning("/proc") {
			t.Error("expected true — an unresolvable exe path must not make the pre-fix comm-only posture worse")
		}
	})

	t.Run("no matching comm", func(t *testing.T) {
		withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
			b.PutDir("/proc", []string{"1"})
			b.PutFile("/proc/1/comm", []byte("init\n"))
		})
		if verifiedAuditdRunning("/proc") {
			t.Error("expected false — no process named auditd")
		}
	})

	t.Run("unreadable proc dir", func(t *testing.T) {
		withCombinedFixture(t, nil, nil, func(b *source.Bundle) {})
		if verifiedAuditdRunning("/proc") {
			t.Error("expected false when /proc itself can't be read")
		}
	})
}

// TestExePathUnderSystemDir covers the allowlist helper directly.
func TestExePathUnderSystemDir(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		want bool
	}{
		{"/sbin/auditd", true},
		{"/usr/sbin/auditd", true},
		{"/usr/lib/auditd/auditd", true},
		{"/bin/auditd", true},
		{"/opt/vendor/auditd", true},
		{"/snap/core/current/auditd", true},
		{"/tmp/evil-payload", false},
		{"/home/attacker/auditd", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := exePathUnderSystemDir(tc.path); got != tc.want {
			t.Errorf("exePathUnderSystemDir(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestIsAuditdPresent guards the standalone gate helper.
func TestIsAuditdPresent(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/auditctl": []byte("/sbin/auditctl"),
		}, nil, nil)
		if !IsAuditdPresent() {
			t.Error("expected true when auditctl is present")
		}
	})

	t.Run("absent", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{}, nil, nil)
		if IsAuditdPresent() {
			t.Error("expected false when auditctl is absent")
		}
	})
}
