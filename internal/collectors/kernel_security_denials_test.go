//go:build linux

package collectors

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestApparmorEnabled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/module/apparmor/parameters/enabled", []byte("Y\n"))
	})
	if !apparmorEnabled() {
		t.Error("enabled=Y should report true")
	}

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/module/apparmor/parameters/enabled", []byte("N\n"))
	})
	if apparmorEnabled() {
		t.Error("enabled=N should report false")
	}
}

func TestApparmorEnabled_ModuleAbsent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if apparmorEnabled() {
		t.Error("missing apparmor module file should report false, not panic")
	}
}

func TestApparmorDetail(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/kernel/security/apparmor/profiles",
			[]byte("/usr/sbin/sshd (enforce)\n/usr/sbin/nginx (complain)\n/usr/lib/lightdm/lightdm (enforce)\n"))
	})
	total, enforce, complain := apparmorDetail()
	if total != 3 || enforce != 2 || complain != 1 {
		t.Errorf("apparmorDetail() = (%d, %d, %d), want (3, 2, 1)", total, enforce, complain)
	}
}

func TestApparmorDetail_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	total, enforce, complain := apparmorDetail()
	if total != 0 || enforce != 0 || complain != 0 {
		t.Errorf("apparmorDetail() with no profiles file = (%d, %d, %d), want zeros", total, enforce, complain)
	}
}

func auditLine(secOffset time.Duration, permissive bool, extra string) string {
	ts := time.Now().Add(secOffset).Unix()
	perm := "permissive=0"
	if permissive {
		perm = "permissive=1"
	}
	return fmt.Sprintf("type=AVC msg=audit(%d.123:45): avc: denied %s %s", ts, extra, perm)
}

func TestCountAVCsFromAuditLog(t *testing.T) {
	lines := []string{
		auditLine(-5*time.Minute, false, `{ read } for pid=100 comm="sshd"`),
		auditLine(-2*time.Hour, false, `{ read } for pid=101 comm="old"`),   // outside 1h window
		auditLine(-5*time.Minute, true, `{ read } for pid=102 comm="perm"`), // permissive, excluded
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/log/audit/audit.log", []byte(strings.Join(lines, "\n")+"\n"))
	})

	n, ok := countAVCsFromAuditLog(1 * time.Hour)
	if !ok {
		t.Fatal("expected ok=true for a readable audit log")
	}
	if n != 1 {
		t.Errorf("expected exactly 1 in-window enforced denial, got %d", n)
	}
}

// TestCountAVCsFromAuditLog_FallsBackToAusearch guards the non-root path:
// audit.log unreadable (absent from the fixture) must fall through to
// ausearch rather than silently returning a false-clean 0.
func TestCountAVCsFromAuditLog_FallsBackToAusearch(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ausearch", []string{"-m", "avc", "-ts", "recent", "--raw"},
			auditLine(-time.Minute, false, `{ read } for pid=200 comm="fromausearch"`)+"\n", 0)
	})

	n, ok := countAVCsFromAuditLog(5 * time.Minute) // <=10min window -> ausearch "recent" ts arg
	if !ok {
		t.Fatal("expected ok=true via the ausearch fallback")
	}
	if n != 1 {
		t.Errorf("expected 1 denial from the ausearch fallback, got %d", n)
	}
}

func TestCountAVCsViaAusearch_NoMatches(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ausearch", []string{"-m", "avc", "-ts", "recent", "--raw"}, "<no matches>\n", 1)
	})
	// ausearch exits non-zero with "<no matches>" on stdout when clean;
	// runCmd surfaces the exit code as an error, which countAVCsViaAusearch
	// must treat as a genuine "0 denials", not "unreadable".
	n, ok := countAVCsViaAusearch(5 * time.Minute)
	if !ok || n != 0 {
		t.Errorf("countAVCsViaAusearch() = (%d, %v), want (0, true) for a clean/absent audit trail", n, ok)
	}
}

func TestCountAppArmorDenials(t *testing.T) {
	lines := []string{
		fmt.Sprintf(`type=AVC msg=audit(%d.123:1): apparmor="DENIED" operation="open" profile="/usr/sbin/nginx" name="/etc/shadow" pid=1 comm="nginx"`, time.Now().Add(-5*time.Minute).Unix()),
		fmt.Sprintf(`type=AVC msg=audit(%d.123:2): apparmor="DENIED" operation="open" profile="/usr/sbin/nginx" name="/etc/passwd" pid=2 comm="nginx"`, time.Now().Add(-2*time.Hour).Unix()),
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/log/audit/audit.log", []byte(strings.Join(lines, "\n")+"\n"))
	})

	n := countAppArmorDenials(1 * time.Hour)
	if n != 1 {
		t.Errorf("expected 1 in-window AppArmor denial, got %d", n)
	}
}

// TestCountAppArmorDenials_FallsBackToDmesg guards the same non-root fallback
// concern as the SELinux path: audit.log unreadable must not silently report 0.
func TestCountAppArmorDenials_FallsBackToDmesg(t *testing.T) {
	since := time.Now().Add(-1 * time.Hour).Format("2006-01-02T15:04:05")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dmesg", []string{"--since", since},
			"[12345.678] audit: type=1400 apparmor=\"DENIED\" operation=\"open\" profile=\"nginx\"\n", 0)
	})

	n := countAppArmorDenials(1 * time.Hour)
	if n != 1 {
		t.Errorf("expected 1 denial from the dmesg fallback, got %d", n)
	}
}

func TestCountAppArmorDenialsDmesg_SinceUnsupportedFallsBackToPlainDmesg(t *testing.T) {
	since := time.Now().Add(-1 * time.Hour).Format("2006-01-02T15:04:05")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dmesg", []string{"--since", since})
		b.PutCmd("dmesg", nil, "kern  :info  : [12345.678] apparmor=\"DENIED\" operation=\"open\"\n", 0)
	})

	n := countAppArmorDenialsDmesg(1 * time.Hour)
	if n != 1 {
		t.Errorf("expected 1 denial from the plain-dmesg fallback, got %d", n)
	}
}

func TestCountAppArmorDenialsDmesg_Unavailable(t *testing.T) {
	since := time.Now().Add(-1 * time.Hour).Format("2006-01-02T15:04:05")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dmesg", []string{"--since", since})
		b.PutCmdNotFound("dmesg", nil)
	})

	n := countAppArmorDenialsDmesg(1 * time.Hour)
	if n != -1 {
		t.Errorf("expected -1 (unverified) when dmesg is entirely unavailable, got %d", n)
	}
}

func TestCollectSELinux_EnforcingWithDenials(t *testing.T) {
	lines := []string{
		auditLine(-5*time.Minute, false, `{ read } for pid=100 comm="sshd"`),
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/fs/selinux/enforce", []byte("1\n"))
		b.PutFile("/var/log/audit/audit.log", []byte(strings.Join(lines, "\n")+"\n"))
	})

	present, mode, denials := collectSELinux(context.Background())
	if !present || mode != "enforcing" {
		t.Fatalf("expected present=true mode=enforcing, got present=%v mode=%q", present, mode)
	}
	if denials != 1 {
		t.Errorf("expected 1 denial, got %d", denials)
	}
}

func TestCollectSELinux_NotPresent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("getenforce", nil)
	})
	present, mode, denials := collectSELinux(context.Background())
	if present || mode != "" || denials != 0 {
		t.Errorf("expected (false, \"\", 0) when SELinux is entirely absent, got (%v, %q, %d)", present, mode, denials)
	}
}

// TestCollectSELinux_DenialsFullyUnreadable guards the -1 sentinel: enforcing
// mode confirmed, but BOTH the audit log and journald are unreadable — must
// report -1 (unverified), never a silent 0 (false-clean).
func TestCollectSELinux_DenialsFullyUnreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/fs/selinux/enforce", []byte("1\n"))
		b.PutCmdNotFound("ausearch", []string{"-m", "avc", "-ts", "recent", "--raw"})
		b.PutCmdNotFound("journalctl", []string{"--since=1 hour ago", "--no-pager", "-q"})
	})

	present, mode, denials := collectSELinux(context.Background())
	if !present || mode != "enforcing" {
		t.Fatalf("expected present=true mode=enforcing, got present=%v mode=%q", present, mode)
	}
	if denials != -1 {
		t.Errorf("expected denials=-1 (unverified) when every denial source is unreadable, got %d", denials)
	}
}
