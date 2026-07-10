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

// ── constructor / interface methods ──────────────────────────────────────────

func TestNewKernelSecurityCollector_NameAndTimeout(t *testing.T) {
	c := NewKernelSecurityCollector()
	if c.Name() != "KernelSec" {
		t.Errorf("Name() = %q, want KernelSec", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

// ── apparmorMode ──────────────────────────────────────────────────────────────

func TestApparmorMode_Enforce(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/kernel/security/apparmor/profiles", []byte("/usr/sbin/sshd (enforce)\n"))
	})
	if got := apparmorMode(); got != "enforce" {
		t.Errorf("apparmorMode() = %q, want enforce", got)
	}
}

func TestApparmorMode_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := apparmorMode(); got != "disabled" {
		t.Errorf("apparmorMode() = %q, want disabled", got)
	}
}

// ── validateSELinuxPolicyType ─────────────────────────────────────────────────

func TestValidateSELinuxPolicyType_Valid(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/selinux/config", []byte("# comment\nSELINUX=enforcing\nSELINUXTYPE=targeted\n"))
		b.PutStat("/etc/selinux/targeted", source.FileMeta{})
		b.PutCmd("rpm", []string{"-q", "selinux-policy-targeted"}, "selinux-policy-targeted-3.14.3-1.fc39.noarch\n", 0)
	})
	seType, typeValid, dirOK, pkgOK, relabel := validateSELinuxPolicyType()
	if seType != "targeted" || !typeValid || !dirOK || !pkgOK || relabel {
		t.Errorf("validateSELinuxPolicyType() = (%q,%v,%v,%v,%v), want (targeted,true,true,true,false)",
			seType, typeValid, dirOK, pkgOK, relabel)
	}
}

func TestValidateSELinuxPolicyType_InvalidType(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/selinux/config", []byte("SELINUXTYPE=permissive\n"))
	})
	seType, typeValid, _, _, _ := validateSELinuxPolicyType()
	if seType != "permissive" || typeValid {
		t.Errorf("validateSELinuxPolicyType() = (%q,%v), want (permissive,false) — not a real policy type", seType, typeValid)
	}
}

func TestValidateSELinuxPolicyType_ConfigAbsent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	seType, typeValid, dirOK, pkgOK, relabel := validateSELinuxPolicyType()
	if seType != "" || typeValid || dirOK || pkgOK || relabel {
		t.Errorf("validateSELinuxPolicyType() = (%q,%v,%v,%v,%v), want all zero/false", seType, typeValid, dirOK, pkgOK, relabel)
	}
}

func TestValidateSELinuxPolicyType_NoSELinuxTypeLine(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/selinux/config", []byte("SELINUX=disabled\n"))
	})
	seType, typeValid, dirOK, pkgOK, relabel := validateSELinuxPolicyType()
	if seType != "" || typeValid || dirOK || pkgOK || relabel {
		t.Errorf("validateSELinuxPolicyType() = (%q,%v,%v,%v,%v), want all zero/false", seType, typeValid, dirOK, pkgOK, relabel)
	}
}

func TestValidateSELinuxPolicyType_RelabelPending(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/selinux/config", []byte("SELINUXTYPE=targeted\n"))
		b.PutStat("/.autorelabel", source.FileMeta{})
	})
	_, _, _, _, relabel := validateSELinuxPolicyType()
	if !relabel {
		t.Error("expected relabelPending=true when /.autorelabel exists")
	}
}

func TestValidateSELinuxPolicyType_DirMissingPkgMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/selinux/config", []byte("SELINUXTYPE=targeted\n"))
		b.PutCmdNotFound("rpm", []string{"-q", "selinux-policy-targeted"})
		b.PutCmdNotFound("dpkg", []string{"-s", "selinux-policy-targeted"})
		b.PutStat("/usr/bin/rpm", source.FileMeta{})
	})
	seType, typeValid, dirOK, pkgOK, _ := validateSELinuxPolicyType()
	if seType != "targeted" || !typeValid || dirOK || pkgOK {
		t.Errorf("validateSELinuxPolicyType() = (%q,%v,dirOK=%v,pkgOK=%v), want dir/pkg both false", seType, typeValid, dirOK, pkgOK)
	}
}

// ── selinuxPolicyPkgInstalled ─────────────────────────────────────────────────

func TestSelinuxPolicyPkgInstalled_ViaRpm(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("rpm", []string{"-q", "selinux-policy-targeted"}, "selinux-policy-targeted-3.14.3-1.fc39.noarch\n", 0)
	})
	if !selinuxPolicyPkgInstalled("targeted") {
		t.Error("expected true when rpm reports the package installed")
	}
}

func TestSelinuxPolicyPkgInstalled_RpmNotInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("rpm", []string{"-q", "selinux-policy-targeted"}, "package selinux-policy-targeted is not installed\n", 1)
		// rpm binary genuinely present (unlike the "no package manager at all"
		// case below) so the function doesn't fall through to the optimistic
		// "can't verify" default.
		b.PutStat("/usr/bin/rpm", source.FileMeta{})
	})
	if selinuxPolicyPkgInstalled("targeted") {
		t.Error("expected false when rpm reports 'not installed'")
	}
}

func TestSelinuxPolicyPkgInstalled_ViaDpkg(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("rpm", []string{"-q", "selinux-policy-targeted"})
		b.PutCmd("dpkg", []string{"-s", "selinux-policy-targeted"}, "Status: install ok installed\n", 0)
	})
	if !selinuxPolicyPkgInstalled("targeted") {
		t.Error("expected true when dpkg reports the package installed")
	}
}

func TestSelinuxPolicyPkgInstalled_NeitherPackageManagerPresent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("rpm", []string{"-q", "selinux-policy-targeted"})
		b.PutCmdNotFound("dpkg", []string{"-s", "selinux-policy-targeted"})
	})
	if !selinuxPolicyPkgInstalled("targeted") {
		t.Error("expected true (optimistic) when neither rpm nor dpkg exists at all")
	}
}

func TestSelinuxPolicyPkgInstalled_PackageManagerPresentButNotInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("rpm", []string{"-q", "selinux-policy-targeted"})
		b.PutCmdNotFound("dpkg", []string{"-s", "selinux-policy-targeted"})
		b.PutStat("/usr/bin/rpm", source.FileMeta{})
	})
	if selinuxPolicyPkgInstalled("targeted") {
		t.Error("expected false when rpm exists but the package genuinely isn't installed")
	}
}

// ── collectAVCSamples ─────────────────────────────────────────────────────────

func TestCollectAVCSamples(t *testing.T) {
	lines := []string{
		auditLine(-5*time.Minute, false, `{ read } for pid=100 comm="sshd"`),
		auditLine(-2*time.Hour, false, `{ read } for pid=101 comm="old"`),   // outside 1h window
		auditLine(-5*time.Minute, true, `{ read } for pid=102 comm="perm"`), // permissive, excluded
		auditLine(-3*time.Minute, false, `{ write } for pid=103 comm="httpd"`),
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/log/audit/audit.log", []byte(strings.Join(lines, "\n")+"\n"))
	})
	samples := collectAVCSamples(3)
	if len(samples) != 2 {
		t.Fatalf("got %d samples, want 2 (in-window, enforced only): %v", len(samples), samples)
	}
}

func TestCollectAVCSamples_CapsAtN(t *testing.T) {
	lines := make([]string, 0, 5)
	for range 5 {
		lines = append(lines, auditLine(-time.Minute, false, `{ read } for pid=100 comm="sshd"`))
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/log/audit/audit.log", []byte(strings.Join(lines, "\n")+"\n"))
	})
	samples := collectAVCSamples(3)
	if len(samples) != 3 {
		t.Errorf("got %d samples, want capped at 3", len(samples))
	}
}

func TestCollectAVCSamples_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if samples := collectAVCSamples(3); samples != nil {
		t.Errorf("expected nil when audit.log is unreadable, got %v", samples)
	}
}

// ── Collect (integration) ────────────────────────────────────────────────────

func TestKernelSecurityCollector_Collect_SELinuxEnforcingWithDenials(t *testing.T) {
	lines := []string{
		auditLine(-5*time.Minute, false, `{ read } for pid=100 comm="sshd"`),
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/fs/selinux/enforce", []byte("1\n"))
		b.PutFile("/var/log/audit/audit.log", []byte(strings.Join(lines, "\n")+"\n"))
		b.PutFile("/etc/selinux/config", []byte("SELINUXTYPE=targeted\n"))
		b.PutStat("/etc/selinux/targeted", source.FileMeta{})
		b.PutCmd("rpm", []string{"-q", "selinux-policy-targeted"}, "installed\n", 0)
	})
	c := NewKernelSecurityCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := result.(*models.KernelSecurityInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.KernelSecurityInfo", result)
	}
	if !info.Available || !info.SELinuxPresent || info.SELinuxMode != "enforcing" {
		t.Errorf("info = %+v, want Available/SELinuxPresent/mode=enforcing", info)
	}
	if info.SELinuxDenials != 1 || len(info.SELinuxAVCSamples) != 1 {
		t.Errorf("info = %+v, want 1 denial with 1 AVC sample", info)
	}
	if info.SELinuxType != "targeted" || !info.SELinuxTypeValid || !info.SELinuxPolicyDirOK || !info.SELinuxPolicyPkgOK {
		t.Errorf("info policy fields = %+v, want targeted/valid/dirOK/pkgOK all true", info)
	}
	if info.AppArmorPresent {
		t.Errorf("expected AppArmorPresent=false (not seeded), got %+v", info)
	}
}

func TestKernelSecurityCollector_Collect_AppArmorEnforcing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/module/apparmor/parameters/enabled", []byte("Y\n"))
		b.PutFile("/sys/kernel/security/apparmor/profiles",
			[]byte("/usr/sbin/sshd (enforce)\n/usr/sbin/nginx (complain)\n"))
		b.PutFile("/var/log/audit/audit.log", []byte("")) // readable, no denials
		b.PutCmdNotFound("getenforce", nil)
	})
	c := NewKernelSecurityCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := result.(*models.KernelSecurityInfo)
	if !info.AppArmorPresent || info.AppArmorMode != "enforce" {
		t.Errorf("info = %+v, want AppArmorPresent=true mode=enforce", info)
	}
	if info.AppArmorProfiles != 2 || info.AppArmorEnforce != 1 || info.AppArmorComplain != 1 {
		t.Errorf("info = %+v, want 2 profiles (1 enforce, 1 complain)", info)
	}
	if info.SELinuxPresent {
		t.Error("expected SELinuxPresent=false (not seeded)")
	}
}

func TestKernelSecurityCollector_Collect_NeitherPresent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("getenforce", nil)
	})
	c := NewKernelSecurityCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := result.(*models.KernelSecurityInfo)
	if !info.Available {
		t.Error("expected Available=true even with neither module present")
	}
	if info.SELinuxPresent || info.AppArmorPresent {
		t.Errorf("info = %+v, want neither present", info)
	}
}
