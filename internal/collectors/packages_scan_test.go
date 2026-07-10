//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestCollectDNF_HappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dnf", []string{"repolist", "--enabled", "-q"}, "repo id   repo name\nbaseos    BaseOS\n", 0)
		// DNF5's "type" column is lowercase "security" (see cve_linux.go's own
		// documented sample format) — capitalizing it would collide with the
		// "Sec"-substring check that distinguishes DNF5's type column from
		// DNF4's "severity/Sec." column and silently misparse as DNF4.
		b.PutCmd("dnf", []string{"advisory", "list", "--security", "--quiet"},
			"RHSA-2026:1234 security  critical openssl-1.2.3.el9.x86_64\nRHSA-2026:5678 security important curl-8.0.1.el9.x86_64\n", 0)
	})

	info, err := collectDNF(context.Background())
	if err != nil {
		t.Fatalf("collectDNF: %v", err)
	}
	if !info.HasSecurityRepo {
		t.Error("expected HasSecurityRepo=true when repolist is non-empty")
	}
	if info.SecurityUpdates != 2 || info.CriticalUpdates != 1 || info.ImportantUpdates != 1 {
		t.Errorf("expected 2 security / 1 critical / 1 important, got %+v", info)
	}
}

func TestCollectDNF_NoSecurityRepo(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dnf", []string{"repolist", "--enabled", "-q"}, "", 0)
	})

	info, err := collectDNF(context.Background())
	if err != nil {
		t.Fatalf("collectDNF: %v", err)
	}
	if info.Status != "no-security-repo" {
		t.Errorf("expected Status=no-security-repo when repolist is empty, got %q", info.Status)
	}
}

// TestCollectDNF_QueryFails guards the false-OK this collector explicitly
// documents: a failed advisory query must report query-failed, never a silent
// clean 0 security updates.
func TestCollectDNF_QueryFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dnf", []string{"repolist", "--enabled", "-q"}, "baseos    BaseOS\n", 0)
		b.PutCmdNotFound("dnf", []string{"advisory", "list", "--security", "--quiet"})
		b.PutCmdNotFound("dnf", []string{"updateinfo", "list", "security", "--quiet"})
	})

	info, err := collectDNF(context.Background())
	if err != nil {
		t.Fatalf("collectDNF: %v", err)
	}
	if info.Status != "query-failed" {
		t.Errorf("expected Status=query-failed when both advisory queries fail, got %q (SecurityUpdates=%d)", info.Status, info.SecurityUpdates)
	}
}

func TestCollectAPT_HappyPath(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {
		b.PutFile("/etc/apt/sources.list", []byte("deb http://security.debian.org/debian-security bookworm-security main\n"))
		b.PutCmd("apt-get", []string{"-s", "upgrade"},
			"Inst openssl [3.0.9-1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])\n"+
				"Inst vim-tiny [2:9.0-8] (2:9.0-8+deb12u1 Debian-Security:12/stable-security [amd64])\n"+
				"0 upgraded, 0 newly installed\n", 0)
		b.PutCmdNotFound("pro", []string{"security-status", "--format", "json"})
	})

	info, err := collectAPT(context.Background())
	if err != nil {
		t.Fatalf("collectAPT: %v", err)
	}
	if !info.HasSecurityRepo {
		t.Error("expected HasSecurityRepo=true once aptHasSecurityRepo() passes (a real gap this pass just fixed)")
	}
	if info.SecurityUpdates != 2 || info.CriticalUpdates != 1 || info.ImportantUpdates != 1 {
		t.Errorf("expected 2 security updates (openssl=Critical per the hardcoded list, vim-tiny=Important), got %+v", info)
	}
}

func TestCollectAPT_NoSecurityRepoConfigured(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {
		b.PutFile("/etc/apt/sources.list", []byte("deb http://deb.debian.org/debian bookworm main\n"))
	})

	info, err := collectAPT(context.Background())
	if err != nil {
		t.Fatalf("collectAPT: %v", err)
	}
	if info.Status != "no-security-repo" {
		t.Errorf("expected Status=no-security-repo when no security mirror is configured, got %q", info.Status)
	}
}

// TestCollectAPT_QueryFails guards the equivalent false-OK for apt: apt-get -s
// upgrade failing (lock held, broken sources) must report query-failed, not a
// silent clean 0.
func TestCollectAPT_QueryFails(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {
		b.PutFile("/etc/apt/sources.list", []byte("deb http://security.debian.org/debian-security bookworm-security main\n"))
		b.PutCmdNotFound("apt-get", []string{"-s", "upgrade"})
	})

	info, err := collectAPT(context.Background())
	if err != nil {
		t.Fatalf("collectAPT: %v", err)
	}
	if info.Status != "query-failed" {
		t.Errorf("expected Status=query-failed when apt-get -s upgrade fails, got %q", info.Status)
	}
}

func TestCollectAPT_KaliCountsAllUpgrades(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=kali\n"))
		b.PutCmd("apt-get", []string{"-s", "upgrade"},
			"Inst openssl [3.0.9-1] (3.0.11-1 Kali:kali-rolling/kali-rolling [amd64])\n", 0)
	})

	info, err := collectAPT(context.Background())
	if err != nil {
		t.Fatalf("collectAPT: %v", err)
	}
	if !info.HasSecurityRepo {
		t.Error("expected HasSecurityRepo=true on Kali (kali-rolling IS the security channel)")
	}
	if info.SecurityUpdates != 1 {
		t.Errorf("expected 1 upgrade counted on Kali without a *-security suite match, got %d", info.SecurityUpdates)
	}
}
