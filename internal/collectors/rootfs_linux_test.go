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
