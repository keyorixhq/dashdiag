//go:build linux

package collectors

import (
	"context"
	"os"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestSecurityCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewSecurityCollector()
	if c.Name() != "Hardening" {
		t.Errorf("Name() = %q, want Hardening", c.Name())
	}
	if c.Timeout() <= 0 {
		t.Error("Timeout() must be positive")
	}
	if NewSecurityCollectorWithProfile(platform.Profile{}) == nil {
		t.Error("NewSecurityCollectorWithProfile must not return nil")
	}
}

// TestSecurityCollector_Collect_Smoke drives the full Collect() wiring against
// an empty fixture — every parse* sub-call must degrade gracefully (its own
// gate returns early) rather than panic when its backing files are absent.
func TestSecurityCollector_Collect_Smoke(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	got, err := NewSecurityCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.SecurityInfo)
	if !info.SSHPubkeyAuth || !info.SSHStrictModes || !info.SSHIgnoreRhosts {
		t.Errorf("expected secure SSH defaults, got %+v", info)
	}
}

func TestParseSSHConfig_SSHDDashT(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("sshd", []string{"-T"}, "permitrootlogin no\npasswordauthentication no\n", 0)
	})
	info := &models.SecurityInfo{}
	parseSSHConfig(info)
	if info.SSHAuditSource != "sshd -T" {
		t.Errorf("SSHAuditSource = %q, want %q", info.SSHAuditSource, "sshd -T")
	}
	if info.SSHPermitRoot || info.SSHPasswordAuth {
		t.Errorf("expected hardened config, got %+v", info)
	}
}

func TestParseSSHConfig_PermissionDeniedFallsBackToFile(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("sshd", []string{"-T"}, "Permission denied\n", 0)
		b.PutFile("/etc/ssh/sshd_config", []byte("PermitRootLogin no\n"))
	})
	info := &models.SecurityInfo{}
	parseSSHConfig(info)
	if info.SSHAuditSource != "file" {
		t.Errorf("SSHAuditSource = %q, want file", info.SSHAuditSource)
	}
	if info.SSHPermitRoot {
		t.Error("expected SSHPermitRoot=false from file fallback")
	}
}

func TestParseSSHConfig_SSHDCommandMissingFallsBackToFile(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("sshd", []string{"-T"})
		b.PutFile("/etc/ssh/sshd_config", []byte("PermitRootLogin yes\n"))
	})
	info := &models.SecurityInfo{}
	parseSSHConfig(info)
	if info.SSHAuditSource != "file" || !info.SSHPermitRoot {
		t.Errorf("expected file source with PermitRootLogin=true, got %+v", info)
	}
}

func TestParseSSHConfig_DropIns(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("sshd", []string{"-T"})
		b.PutFile("/etc/ssh/sshd_config", []byte("Include /etc/ssh/sshd_config.d/*.conf\n"))
		b.PutGlob("/etc/ssh/sshd_config.d/*.conf", []string{"/etc/ssh/sshd_config.d/50-cloud-init.conf"})
		b.PutFile("/etc/ssh/sshd_config.d/50-cloud-init.conf", []byte("PasswordAuthentication yes\n"))
	})
	info := &models.SecurityInfo{}
	parseSSHConfig(info)
	if info.SSHAuditSource != "file" {
		t.Errorf("SSHAuditSource = %q, want file", info.SSHAuditSource)
	}
	if !info.SSHPasswordAuth {
		t.Error("expected drop-in's PasswordAuthentication=yes to be applied")
	}
}

func TestParseSSHConfig_NoFilesFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("sshd", []string{"-T"})
	})
	info := &models.SecurityInfo{}
	parseSSHConfig(info)
	if info.SSHAuditSource != "" {
		t.Errorf("SSHAuditSource = %q, want empty when nothing readable", info.SSHAuditSource)
	}
}

// TestParseSSHFile_NotFound covers the not-found branch — the Bundle fixture
// API has no way to seed a genuine permission-denied read (only PutFile's
// success case), so the permission branch (which sets SSHConfigUnreadable)
// stays untested here, matching the same absent-vs-unreadable distinction
// already established for parsePasswordAging's shadow-file handling.
func TestParseSSHFile_NotFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	info := &models.SecurityInfo{}
	got := parseSSHFile("/etc/ssh/sshd_config", info)
	if got {
		t.Error("expected false when sshd_config not seeded (not found)")
	}
	if info.SSHConfigUnreadable {
		t.Error("a not-found file must not set SSHConfigUnreadable (that's for permission-denied only)")
	}
}

func TestParseListeningPorts_Happy(t *testing.T) {
	withReadlinkFixture(t, map[string]string{
		"/proc/1234/fd/3": "socket:[9999]",
	}, func(b *source.Bundle) {
		b.PutFile("/proc/net/tcp",
			[]byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
				"   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9999 1 0000000000000000 100 0 0 10 0\n"))
		b.PutFile("/proc/net/tcp6", []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"))
		b.PutGlob("/proc/[0-9]*/fd", []string{"/proc/1234/fd"})
		b.PutFile("/proc/1234/comm", []byte("nginx\n"))
		b.PutDir("/proc/1234/fd", []string{"3"})
	})
	info := &models.SecurityInfo{}
	parseListeningPorts(info)
	if len(info.ListeningPorts) != 1 {
		t.Fatalf("expected 1 listening port, got %d: %+v", len(info.ListeningPorts), info.ListeningPorts)
	}
	p := info.ListeningPorts[0]
	if p.Port != 8080 || p.Process != "nginx" {
		t.Errorf("port = %+v, want port=8080 process=nginx", p)
	}
}

func TestParseListeningPorts_NoRootNoProcessNames(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/tcp",
			[]byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
				"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"))
		b.PutFile("/proc/net/tcp6", []byte(""))
	})
	info := &models.SecurityInfo{}
	parseListeningPorts(info)
	if len(info.ListeningPorts) != 1 || info.ListeningPorts[0].Port != 22 {
		t.Fatalf("expected port 22, got %+v", info.ListeningPorts)
	}
	if !info.PortsNeedRoot {
		t.Error("expected PortsNeedRoot=true when the fd scan found nothing")
	}
}

func TestParseListeningPorts_NonWildcardAddrSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// Local addr 0100007F = 127.0.0.1 — not a wildcard bind, must be skipped.
		b.PutFile("/proc/net/tcp",
			[]byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
				"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9999 1 0000000000000000 100 0 0 10 0\n"))
		b.PutFile("/proc/net/tcp6", []byte(""))
	})
	info := &models.SecurityInfo{}
	parseListeningPorts(info)
	if len(info.ListeningPorts) != 0 {
		t.Errorf("expected 0 ports (127.0.0.1 bind is not 0.0.0.0), got %+v", info.ListeningPorts)
	}
}

func TestBuildInodeProcMap_Happy(t *testing.T) {
	withReadlinkFixture(t, map[string]string{
		"/proc/100/fd/5": "socket:[555]",
		"/proc/100/fd/6": "/dev/null",
	}, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*/fd", []string{"/proc/100/fd"})
		b.PutFile("/proc/100/comm", []byte("sshd\n"))
		b.PutDir("/proc/100/fd", []string{"5", "6"})
	})
	m, hasRoot := buildInodeProcMap()
	if !hasRoot {
		t.Fatal("expected hasRoot=true")
	}
	if m["555"] != "sshd" {
		t.Errorf("m[555] = %q, want sshd", m["555"])
	}
}

func TestBuildInodeProcMap_NoProcesses(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	m, hasRoot := buildInodeProcMap()
	if hasRoot {
		t.Error("expected hasRoot=false when the glob finds nothing")
	}
	if len(m) != 0 {
		t.Errorf("expected empty map, got %v", m)
	}
}

func TestParseSELinuxDenials_Enforcing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/fs/selinux/enforce", []byte("1\n"))
	})
	info := &models.SecurityInfo{}
	parseSELinuxDenials(context.Background(), info)
	if info.SELinuxMode != "enforcing" {
		t.Errorf("SELinuxMode = %q, want enforcing", info.SELinuxMode)
	}
	// Neither audit.log nor ausearch is seeded — must fall back to the unknown sentinel.
	if info.SELinuxDenials != -1 {
		t.Errorf("SELinuxDenials = %d, want -1 (unknown, no audit source readable)", info.SELinuxDenials)
	}
}

func TestParseSELinuxDenials_Permissive(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/fs/selinux/enforce", []byte("0\n"))
	})
	info := &models.SecurityInfo{}
	parseSELinuxDenials(context.Background(), info)
	if info.SELinuxMode != "permissive" {
		t.Errorf("SELinuxMode = %q, want permissive", info.SELinuxMode)
	}
}

func TestParseSELinuxDenials_NotPresent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	info := &models.SecurityInfo{}
	parseSELinuxDenials(context.Background(), info)
	if info.SELinuxMode != "" {
		t.Errorf("SELinuxMode = %q, want empty (SELinux absent)", info.SELinuxMode)
	}
}

func TestScanSUIDBinaries_UnexpectedFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/usr/local", []string{"evil-suid"})
		b.PutStat("/usr/local/evil-suid", source.FileMeta{Mode: 0o4755 | os.ModeSetuid})
		b.PutDir("/opt", nil)
		b.PutDir("/home", nil)
		b.PutDir("/tmp", nil)
		b.PutDir("/var/tmp", nil)
	})
	info := &models.SecurityInfo{}
	ScanSUIDBinaries(info)
	if len(info.SUIDBinaries) != 1 || info.SUIDBinaries[0] != "/usr/local/evil-suid" {
		t.Errorf("SUIDBinaries = %v, want [/usr/local/evil-suid]", info.SUIDBinaries)
	}
}

func TestFindUnexpectedSUIDs_KnownBinarySkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/usr/local", nil)
		b.PutDir("/opt", nil)
		b.PutDir("/home", nil)
		b.PutDir("/tmp", []string{"passwd-shadow-copy"})
		b.PutStat("/tmp/passwd-shadow-copy", source.FileMeta{Mode: 0o644}) // not setuid
		b.PutDir("/var/tmp", nil)
	})
	info := &models.SecurityInfo{}
	findUnexpectedSUIDs(info)
	if len(info.SUIDBinaries) != 0 {
		t.Errorf("expected no SUID binaries flagged, got %v", info.SUIDBinaries)
	}
}

func TestFindUnexpectedSUIDs_NestedDir(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/usr/local", []string{"bin"})
		b.PutDir("/usr/local/bin", []string{"tool"})
		b.PutStat("/usr/local/bin/tool", source.FileMeta{Mode: 0o755 | os.ModeSetuid})
		b.PutDir("/opt", nil)
		b.PutDir("/home", nil)
		b.PutDir("/tmp", nil)
		b.PutDir("/var/tmp", nil)
	})
	info := &models.SecurityInfo{}
	findUnexpectedSUIDs(info)
	if len(info.SUIDBinaries) != 1 || info.SUIDBinaries[0] != "/usr/local/bin/tool" {
		t.Errorf("SUIDBinaries = %v, want [/usr/local/bin/tool] (recurse into subdir)", info.SUIDBinaries)
	}
}

func TestParseSELinuxExtras_AutoRelabel(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/.autorelabel", source.FileMeta{})
	})
	info := &models.SecurityInfo{}
	parseSELinuxExtras(context.Background(), info)
	if !info.SELinuxAutoRelabel {
		t.Error("expected SELinuxAutoRelabel=true when /.autorelabel exists")
	}
}

func TestParseSELinuxExtras_NoAutoRelabel(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	info := &models.SecurityInfo{}
	parseSELinuxExtras(context.Background(), info)
	if info.SELinuxAutoRelabel {
		t.Error("expected SELinuxAutoRelabel=false when /.autorelabel absent")
	}
}
