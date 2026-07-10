//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── aptHasSecurityRepo ───────────────────────────────────────────────────────

func TestAptHasSecurityRepo_MainSourcesList(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/apt/sources.list", []byte(
			"# comment, ignored\n"+
				"\n"+
				"deb http://archive.ubuntu.com/ubuntu noble main\n"+
				"deb http://security.ubuntu.com/ubuntu noble-security main\n"))
	})
	if !aptHasSecurityRepo() {
		t.Error("expected true: sources.list contains a security.ubuntu.com line")
	}
}

func TestAptHasSecurityRepo_SourcesListD(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/apt/sources.list", []byte("deb http://archive.ubuntu.com/ubuntu noble main\n"))
		b.PutDir("/etc/apt/sources.list.d", []string{"debian.sources", "some-dir"})
		b.PutFile("/etc/apt/sources.list.d/debian.sources", []byte("URIs: http://deb.debian.org/debian-security\n"))
	})
	if !aptHasSecurityRepo() {
		t.Error("expected true: a sources.list.d file names a -security repo")
	}
}

func TestAptHasSecurityRepo_NoneFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/apt/sources.list", []byte("deb http://archive.ubuntu.com/ubuntu noble main\n"))
	})
	if aptHasSecurityRepo() {
		t.Error("expected false: no line mentions a security repo")
	}
}

func TestAptHasSecurityRepo_FilesUnreadable(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // neither sources.list nor .d seeded
	if aptHasSecurityRepo() {
		t.Error("expected false when no apt source files are readable")
	}
}

// ── collectPackageIntegrity dispatcher (apt/zypper branches) ────────────────
//
// TestCollectPackageIntegrity_DNF and _UnknownManagerStillRunsCrossDistroChecks
// (packages_scanners2_test.go) already cover the dnf and default branches.

func TestCollectPackageIntegrity_Apt(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("apt-get", []string{"check"}, "", 0)
		b.PutCmd("dpkg", []string{"--audit"}, "", 0)
		b.PutCmd("ldconfig", []string{"-p"}, "libc.so.6 (libc6,x86-64) => /lib/x86_64-linux-gnu/libc.so.6\n", 0)
	})
	pi := collectPackageIntegrity(context.Background(), "apt")
	if !pi.LdconfigOK {
		t.Error("expected LdconfigOK=true")
	}
	if len(pi.BrokenPackages) != 0 || len(pi.UnmetDeps) != 0 {
		t.Errorf("expected a clean apt integrity result, got %+v", pi)
	}
}

func TestCollectPackageIntegrity_Zypper(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--non-interactive", "verify", "--dry-run"}, "Nothing to do.\n", 0)
		b.PutCmd("ldconfig", []string{"-p"}, "libc.so.6 (libc6,x86-64) => /lib/x86_64-linux-gnu/libc.so.6\n", 0)
	})
	pi := collectPackageIntegrity(context.Background(), "zypper")
	if !pi.LdconfigOK {
		t.Error("expected LdconfigOK=true")
	}
	if len(pi.BrokenPackages) != 0 {
		t.Errorf("expected a clean zypper integrity result, got %+v", pi)
	}
}

// ── pkgIntegrityZypper ───────────────────────────────────────────────────────
//
// TestPkgIntegrityZypperNonZeroExit (packages_integrity_linux_test.go) already
// covers the exit-1 "problems found" branch. These add: the clean (exit 0, no
// findings) branch and the lock-exhausted branch (VerifyLocked, not a false
// "clean" result — the #481 false-OK class).

func TestPkgIntegrityZypper_Clean(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--non-interactive", "verify", "--dry-run"}, "Nothing to do.\n", 0)
	})
	pi := &models.PackageIntegrity{}
	pkgIntegrityZypper(context.Background(), pi)
	if pi.VerifyLocked {
		t.Error("expected VerifyLocked=false for a clean, unlocked verify")
	}
	if len(pi.BrokenPackages) != 0 {
		t.Errorf("expected no BrokenPackages for a clean verify, got %+v", pi.BrokenPackages)
	}
}

func TestPkgIntegrityZypper_LockedExhaustsRetries(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--non-interactive", "verify", "--dry-run"},
			"System management is locked by the application with pid 1 (zypper).", 7)
	})
	// Pre-cancel the context so sleepCtx's retry-wait returns false immediately —
	// exercises the lock-retry loop without a real ~3.2s sleep (4 attempts × 800ms).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pi := &models.PackageIntegrity{}
	pkgIntegrityZypper(ctx, pi)
	if !pi.VerifyLocked {
		t.Fatal("expected VerifyLocked=true when the zypp lock is held for every retry (must not read as a silent clean)")
	}
	if len(pi.BrokenPackages) != 0 {
		t.Errorf("a locked verify must not report BrokenPackages, got %+v", pi.BrokenPackages)
	}
}
