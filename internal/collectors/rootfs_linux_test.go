//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestNewRootFSCollector_Identity pins the constructor and identity methods
// (Name/Timeout) — these touch no fixture source, so t.Parallel() is safe.
func TestNewRootFSCollector_Identity(t *testing.T) {
	t.Parallel()
	c := NewRootFSCollector()
	if c == nil {
		t.Fatal("NewRootFSCollector returned nil")
	}
	if got, want := c.Name(), "Root FS"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
	if got, want := c.Timeout(), 2*time.Second; got != want {
		t.Errorf("Timeout() = %v, want %v", got, want)
	}
}

// The fault is narrow: a read-only root only matters on a normally-writable fs,
// when fstab intends rw, and nothing makes it ro by design.
func TestRootROIsUnexpected(t *testing.T) {
	cases := []struct {
		name      string
		fstype    string
		fstabRW   bool
		immutable bool
		want      bool
	}{
		{"broken ext4 (remount-ro trip)", "ext4", true, false, true},
		{"broken xfs", "xfs", true, false, true},
		{"broken btrfs", "btrfs", true, false, true},
		{"immutable distro (ostree/microos/steamos)", "btrfs", true, true, false},
		{"immutable image fstype", "squashfs", true, false, false},
		{"erofs live media", "erofs", true, false, false},
		{"fstab declares ro (intended)", "ext4", false, false, false},
		{"overlay root", "overlay", true, false, false},
	}
	for _, tc := range cases {
		if got := rootROIsUnexpected(tc.fstype, tc.fstabRW, tc.immutable); got != tc.want {
			t.Errorf("%s: rootROIsUnexpected(%q,%v,%v)=%v want %v", tc.name, tc.fstype, tc.fstabRW, tc.immutable, got, tc.want)
		}
	}
}

// TestOsReleaseIsSteamOS guards the three branches: SteamOS via ID=, SteamOS
// via the steamdeck VARIANT_ID, and a non-SteamOS distro (must not flag).
func TestOsReleaseIsSteamOS(t *testing.T) {
	t.Run("ID=steamos", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/etc/os-release", []byte("NAME=SteamOS\nID=steamos\nVERSION_ID=3.5\n"))
		})
		if !osReleaseIsSteamOS() {
			t.Error("expected true for ID=steamos")
		}
	})

	t.Run("VARIANT_ID=steamdeck", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/etc/os-release", []byte("NAME=SteamOS\nID=steamos\nVARIANT_ID=steamdeck\n"))
		})
		if !osReleaseIsSteamOS() {
			t.Error("expected true for VARIANT_ID=steamdeck")
		}
	})

	t.Run("non-SteamOS distro", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/etc/os-release", []byte("NAME=Ubuntu\nID=ubuntu\n"))
		})
		if osReleaseIsSteamOS() {
			t.Error("expected false for a non-SteamOS distro")
		}
	})

	t.Run("file missing", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		if osReleaseIsSteamOS() {
			t.Error("expected false when /etc/os-release is unreadable")
		}
	})
}

// TestRootImmutableByDesign covers all three markers (ostree, transactional-update
// under either path, SteamOS via os-release) plus the negative case.
func TestRootImmutableByDesign(t *testing.T) {
	t.Run("ostree", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/run/ostree-booted", source.FileMeta{})
		})
		if !rootImmutableByDesign() {
			t.Error("expected true when /run/ostree-booted exists")
		}
	})

	t.Run("transactional-update usr sbin", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/usr/sbin/transactional-update", source.FileMeta{})
		})
		if !rootImmutableByDesign() {
			t.Error("expected true when /usr/sbin/transactional-update exists")
		}
	})

	t.Run("transactional-update sbin", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/sbin/transactional-update", source.FileMeta{})
		})
		if !rootImmutableByDesign() {
			t.Error("expected true when /sbin/transactional-update exists")
		}
	})

	t.Run("steamos via os-release", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/etc/os-release", []byte("NAME=SteamOS\nID=steamos\n"))
		})
		if !rootImmutableByDesign() {
			t.Error("expected true for SteamOS via os-release fallback")
		}
	})

	t.Run("none of the markers present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/etc/os-release", []byte("NAME=Ubuntu\nID=ubuntu\n"))
		})
		if rootImmutableByDesign() {
			t.Error("expected false when no immutable marker is present")
		}
	})
}

// TestFstabIntendsRootRW covers the readFile-wrapping wrapper directly: file
// absent (can't confirm → false) and a real rw `/` entry (true), matching the
// pure fstabRootRW cases already covered above but through the injectable path.
func TestFstabIntendsRootRW(t *testing.T) {
	t.Run("fstab absent", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		if fstabIntendsRootRW() {
			t.Error("expected false when /etc/fstab is unreadable")
		}
	})

	t.Run("root entry with rw intent", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/etc/fstab", []byte("/dev/sda1 / ext4 defaults 0 1\n"))
		})
		if !fstabIntendsRootRW() {
			t.Error("expected true for a `/` entry with no ro option")
		}
	})

	t.Run("root entry with explicit ro", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/etc/fstab", []byte("UUID=x / btrfs ro,subvol=@ 0 0\n"))
		})
		if fstabIntendsRootRW() {
			t.Error("expected false for a `/` entry with explicit ro")
		}
	})
}

func TestFstabRootRW(t *testing.T) {
	// errors=remount-ro is rw intent (the `ro` is a substring, not the option).
	if !fstabRootRW("UUID=x / ext4 errors=remount-ro 0 1") {
		t.Error("errors=remount-ro must read as rw intent")
	}
	if !fstabRootRW("/dev/sda1 / ext4 rw,discard,errors=remount-ro,x-systemd.growfs 0 1") {
		t.Error("explicit rw must read as rw intent")
	}
	// An explicit `ro` option means ro is intended (immutable-style fstab).
	if fstabRootRW("UUID=x / btrfs ro,subvol=@ 0 0") {
		t.Error("an explicit ro option is intended ro, not a fault")
	}
	// No `/` entry → can't confirm rw intent → false (don't flag).
	if fstabRootRW("UUID=x /boot ext4 defaults 0 2\ntmpfs /tmp tmpfs defaults 0 0") {
		t.Error("no root entry must not read as rw intent")
	}
}

// End-to-end Collect() over an injected source: a ro root on ext4 with an rw fstab
// and no immutable markers → UnexpectedReadOnly. Proves the full pipeline (readMounts
// → find / → guards → fstab intent) without needing a real (un-inducible) ro root.
func TestRootFSCollect_EndToEnd(t *testing.T) {
	withMounts := func(mounts, fstab string) *models.RootFSInfo {
		b := source.NewBundle()
		b.PutFile("/proc/mounts", []byte(mounts))
		b.PutFile("/etc/fstab", []byte(fstab))
		restore := SetSource(source.NewReplay(b))
		defer SetSource(restore)
		out, _ := (&RootFSCollector{}).Collect(context.Background())
		if out == nil {
			return nil
		}
		return out.(*models.RootFSInfo)
	}

	// ro root, ext4, fstab rw, no markers → fault.
	got := withMounts(
		"sysfs /sys sysfs rw 0 0\n/dev/sda1 / ext4 ro,relatime,errors=remount-ro 0 0\n",
		"/dev/sda1 / ext4 errors=remount-ro 0 1\n",
	)
	if got == nil || !got.UnexpectedReadOnly || got.RootFstype != "ext4" {
		t.Fatalf("ro root with rw fstab must flag, got %+v", got)
	}

	// rw root → no row.
	if got := withMounts("/dev/sda1 / ext4 rw,relatime 0 0\n", "/dev/sda1 / ext4 defaults 0 1\n"); got != nil {
		t.Errorf("rw root must produce no result, got %+v", got)
	}

	// ro root but fstab declares ro (immutable-style) → no flag.
	if got := withMounts("/dev/sda1 / btrfs ro,subvol=@ 0 0\n", "/dev/sda1 / btrfs ro,subvol=@ 0 0\n"); got != nil {
		t.Errorf("intended-ro root must not flag, got %+v", got)
	}
}

// TestRootFSCollect_MountsReadError covers rootfs_linux.go:36.16,38.3 — the
// early return when /proc/mounts is unreadable. Collect must return (nil, nil)
// without propagating an error (the contract: nothing to assert, stay quiet).
func TestRootFSCollect_MountsReadError(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // /proc/mounts not seeded
	c := &RootFSCollector{}
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("Collect() = %v, want nil when /proc/mounts is unreadable", raw)
	}
}
