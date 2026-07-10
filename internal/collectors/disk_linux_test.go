//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── zfsGate ──────────────────────────────────────────────────────────────────
//
// No t.Parallel() in this group: these swap the package-level activeSource via
// SetSource, which is only race-free when serial tests finish before the
// parallel batch starts (same constraint documented for runCmd/lookPath swaps
// in internal/drilldown).

func TestZFSGate_NoZpoolTool(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {})
	if zfsGate() {
		t.Error("expected false when zpool is not on PATH")
	}
}

func TestZFSGate_NoZFSMount(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"zpool": true}, func(b *source.Bundle) {
		b.PutFile("/proc/mounts", []byte("/dev/sda1 / ext4 rw,relatime 0 0\ntmpfs /run tmpfs rw 0 0\n"))
	})
	if zfsGate() {
		t.Error("expected false when no live zfs mount is present")
	}
}

func TestZFSGate_LiveZFSMount(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"zpool": true}, func(b *source.Bundle) {
		b.PutFile("/proc/mounts", []byte("/dev/sda1 / ext4 rw,relatime 0 0\ntank /tank zfs rw,xattr,noacl 0 0\n"))
	})
	if !zfsGate() {
		t.Error("expected true when zpool is present and a zfs mount is live")
	}
}

func TestZFSGate_MountsUnreadable(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"zpool": true}, func(b *source.Bundle) {}) // /proc/mounts never seeded
	if zfsGate() {
		t.Error("expected false when /proc/mounts can't be read")
	}
}

// ── deviceSizeBytes / deviceKernelName ──────────────────────────────────────
//
// No t.Parallel() here either (SetSource swap), except the one sub-test that
// never touches activeSource.

func TestDeviceSizeBytes_DirectNode(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/sys/class/block/sda1", source.FileMeta{})
		b.PutFile("/sys/class/block/sda1/size", []byte("204800\n")) // 100MiB in 512B sectors
	})
	got, ok := deviceSizeBytes("/dev/sda1")
	if !ok {
		t.Fatal("expected ok=true for a direct device node with a readable size file")
	}
	if got != 204800*512 {
		t.Errorf("deviceSizeBytes = %d, want %d", got, 204800*512)
	}
}

func TestDeviceSizeBytes_SymlinkResolvedOneHop(t *testing.T) {
	// /dev/mapper/vg-lv is not itself a /sys/class/block entry — resolve via
	// readlink to dm-0. Bundle has no public Readlink-seeding API, so use the
	// package's shared fakeCombinedSource (see security_linux_source_test.go).
	withCombinedFixture(t, nil, map[string]string{"/dev/mapper/vg-lv": "../dm-0"}, func(b *source.Bundle) {
		b.PutStat("/sys/class/block/dm-0", source.FileMeta{})
		b.PutFile("/sys/class/block/dm-0/size", []byte("1024\n"))
	})
	got, ok := deviceSizeBytes("/dev/mapper/vg-lv")
	if !ok {
		t.Fatal("expected ok=true when the symlink resolves to a real block device")
	}
	if got != 1024*512 {
		t.Errorf("deviceSizeBytes = %d, want %d", got, 1024*512)
	}
}

func TestDeviceSizeBytes_NotAKnownBlockDevice(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {}) // nothing seeded — neither direct nor symlink resolves
	if _, ok := deviceSizeBytes("/dev/does-not-exist"); ok {
		t.Error("expected ok=false when the device can't be mapped to a sysfs entry")
	}
}

func TestDeviceSizeBytes_NotADevPath(t *testing.T) {
	t.Parallel()
	if _, ok := deviceSizeBytes("relative/path"); ok {
		t.Error("expected ok=false for a path not under /dev/")
	}
}

func TestDeviceSizeBytes_UnparsableSize(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/sys/class/block/sda1", source.FileMeta{})
		b.PutFile("/sys/class/block/sda1/size", []byte("not-a-number\n"))
	})
	if _, ok := deviceSizeBytes("/dev/sda1"); ok {
		t.Error("expected ok=false when the sysfs size file is unparsable")
	}
}

func TestDeviceSizeBytes_ZeroOrNegativeSizeRejected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/sys/class/block/sda1", source.FileMeta{})
		b.PutFile("/sys/class/block/sda1/size", []byte("0\n"))
	})
	if _, ok := deviceSizeBytes("/dev/sda1"); ok {
		t.Error("expected ok=false for a zero-sector size (never claim a real disk is 0 bytes)")
	}
}

// fakeStatfsSource layers a Statfs override (Bundle has no public Statfs-seeding
// API) on top of a Bundle-backed Replay, mirroring fakeCombinedSource's
// Cached/Readlink override pattern (see security_linux_source_test.go) — so
// DiskCollector.Collect can be driven end to end without touching the real
// filesystem.
type fakeStatfsSource struct {
	*source.Replay
	statfs map[string]source.StatfsInfo
}

func (f *fakeStatfsSource) Statfs(path string) (source.StatfsInfo, error) {
	if v, ok := f.statfs[path]; ok {
		return v, nil
	}
	return f.Replay.Statfs(path)
}

// withStatfsFixture seeds a Bundle (PutFile/PutStat/...) and a mount-point ->
// StatfsInfo map into one active source for the test's duration.
func withStatfsFixture(t *testing.T, statfs map[string]source.StatfsInfo, seed func(b *source.Bundle)) {
	t.Helper()
	b := source.NewBundle()
	if seed != nil {
		seed(b)
	}
	prev := SetSource(&fakeStatfsSource{Replay: source.NewReplay(b), statfs: statfs})
	t.Cleanup(func() { SetSource(prev) })
}

func TestDiskCollectorIdentity(t *testing.T) {
	t.Parallel()
	deep := NewDiskDeepCollector()
	if deep.Name() != "Disk" {
		t.Errorf("Name() = %q, want Disk", deep.Name())
	}
	if !deep.Deep {
		t.Error("NewDiskDeepCollector() must set Deep=true")
	}
	if deep.Timeout() != 12*time.Second {
		t.Errorf("deep Timeout() = %v, want 12s", deep.Timeout())
	}

	cc := platform.ContainerContext{InContainer: true}
	normal := NewDiskCollector(cc)
	if normal.Deep {
		t.Error("NewDiskCollector() must not set Deep")
	}
	if normal.Timeout() != 5*time.Second {
		t.Errorf("normal Timeout() = %v, want 5s", normal.Timeout())
	}
	if normal.ContainerCtx != cc {
		t.Errorf("ContainerCtx = %+v, want %+v", normal.ContainerCtx, cc)
	}
}

func TestSkipMacOSMount(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		fstype     string
		mountpoint string
		want       bool
	}{
		{"devfs skipped", "devfs", "/dev", true},
		{"autofs skipped", "autofs", "/net", true},
		{"synthfs skipped", "synthfs", "/private/var/vm", true},
		{"bindfs skipped", "bindfs", "/mnt/bind", true},
		{"/dev mountpoint skipped regardless of fstype", "hfs", "/dev", true},
		{"synthetic system volume skipped", "apfs", "/System/Volumes/Preboot", true},
		{"Data system volume kept", "apfs", "/System/Volumes/Data", false},
		{"real root volume kept", "apfs", "/", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := skipMacOSMount(tt.fstype, tt.mountpoint); got != tt.want {
				t.Errorf("skipMacOSMount(%q, %q) = %v, want %v", tt.fstype, tt.mountpoint, got, tt.want)
			}
		})
	}
}

// TestDiskCollector_Collect_FiltersAndComputes drives Collect() end to end: a
// skippable tmpfs mount, a /proc-prefixed mount, and a real ext4 mount — only
// the surviving ext4 mount should end up in Filesystems, with Total/Free/Used
// computed from the seeded Statfs numbers.
func TestDiskCollector_Collect_FiltersAndComputes(t *testing.T) {
	withStatfsFixture(t, map[string]source.StatfsInfo{
		"/": {
			Bsize:  4096,
			Blocks: 2500000, // ~10.24GB total
			Bfree:  1250000, // ~5.12GB free
			Bavail: 1250000,
			Files:  655360,
			Ffree:  327680, // 50% inodes used
		},
	}, func(b *source.Bundle) {
		b.PutFile("/proc/mounts",
			[]byte("tmpfs /run tmpfs rw,nosuid,nodev 0 0\n"+
				"proc /proc/self/status proc rw 0 0\n"+
				"/dev/sda1 / ext4 rw,relatime 0 0\n"))
	})

	c := NewDiskCollector(platform.ContainerContext{InContainer: true}) // container: skip SMART/etc probes
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.DiskInfo)
	if len(info.Filesystems) != 1 {
		t.Fatalf("Filesystems = %+v, want exactly 1 (tmpfs and /proc/self/status must be skipped)", info.Filesystems)
	}
	fs := info.Filesystems[0]
	if fs.Mount != "/" || fs.Device != "/dev/sda1" || fs.FSType != "ext4" {
		t.Errorf("fs = %+v, want mount=/ device=/dev/sda1 fstype=ext4", fs)
	}
	wantTotalGB := 2500000.0 * 4096 / 1e9
	if fs.TotalGB != wantTotalGB {
		t.Errorf("TotalGB = %v, want %v", fs.TotalGB, wantTotalGB)
	}
	wantFreeGB := 1250000.0 * 4096 / 1e9
	if fs.FreeGB != wantFreeGB {
		t.Errorf("FreeGB = %v, want %v", fs.FreeGB, wantFreeGB)
	}
	if fs.UsedGB != wantTotalGB-wantFreeGB {
		t.Errorf("UsedGB = %v, want %v", fs.UsedGB, wantTotalGB-wantFreeGB)
	}
	if fs.UsedPct != 50 {
		t.Errorf("UsedPct = %v, want 50", fs.UsedPct)
	}
	if fs.InodesUsedPct != 50 {
		t.Errorf("InodesUsedPct = %v, want 50", fs.InodesUsedPct)
	}
}

// TestDiskCollector_Collect_MountsUnreadable guards the error path: if
// /proc/mounts can't be opened (not seeded in the bundle), Collect() must
// return an error rather than a silently-empty DiskInfo.
func TestDiskCollector_Collect_MountsUnreadable(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // /proc/mounts never seeded

	c := NewDiskCollector(platform.ContainerContext{})
	if _, err := c.Collect(context.Background()); err == nil {
		t.Error("Collect() error = nil, want an error when /proc/mounts is unreadable")
	}
}

// parseSMARTHealth must return a verdict whenever smartctl prints one — including
// for a FAILING drive, whose `smartctl -H` exits non-zero but still prints
// "...result: FAILED!". Returning ok=false there would let collectSMART set an
// Error and the analysis layer would skip the drive entirely — silently dropping
// the one drive we most need to flag.
func TestParseSMARTHealth(t *testing.T) {
	cases := []struct {
		name        string
		out         string
		wantHealthy bool
		wantOK      bool
	}{
		{
			name:        "SATA/NVMe passed",
			out:         "smartctl 7.4\n\nSMART overall-health self-assessment test result: PASSED\n",
			wantHealthy: true, wantOK: true,
		},
		{
			name:        "SATA/NVMe failing (non-zero exit, verdict still on stdout)",
			out:         "smartctl 7.4\n\nSMART overall-health self-assessment test result: FAILED!\n",
			wantHealthy: false, wantOK: true,
		},
		{
			name:        "SAS OK",
			out:         "SMART Health Status: OK\n",
			wantHealthy: true, wantOK: true,
		},
		{
			name:        "SAS failing",
			out:         "SMART Health Status: FAILED\n",
			wantHealthy: false, wantOK: true,
		},
		{
			name:        "no verdict line",
			out:         "smartctl 7.4\nUnable to detect device type\n",
			wantHealthy: false, wantOK: false,
		},
		{
			name:        "empty output",
			out:         "",
			wantHealthy: false, wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			healthy, ok := parseSMARTHealth(tc.out)
			if healthy != tc.wantHealthy || ok != tc.wantOK {
				t.Errorf("parseSMARTHealth = (healthy=%v, ok=%v), want (%v, %v)",
					healthy, ok, tc.wantHealthy, tc.wantOK)
			}
		})
	}
}

// parseSMARTAttributes must never let a negative count reach a counter: the
// analysis layer flags a drive on `MediaErrors > 0`, so a garbled or hostile
// SMART log printing "-5" would slip under the threshold and read as healthy —
// a false-OK. Valid non-negative values must still parse.
func TestParseSMARTAttributesNegativeRejected(t *testing.T) {
	var s models.SMARTInfo
	parseSMARTAttributes(
		"Media and Data Integrity Errors:  -5\n"+
			"Percentage Used:  -3%\n"+
			"Power On Hours:  -1\n",
		&s)
	if s.MediaErrors != 0 || s.PercentUsed != 0 || s.PowerOnHours != 0 {
		t.Errorf("negative SMART values leaked into counters: media=%d pct=%d poh=%d (want 0,0,0)",
			s.MediaErrors, s.PercentUsed, s.PowerOnHours)
	}

	// Valid values must still be read.
	var ok models.SMARTInfo
	parseSMARTAttributes(
		"Media and Data Integrity Errors:  2\n"+
			"Percentage Used:  7%\n"+
			"Power On Hours:  7,183\n",
		&ok)
	if ok.MediaErrors != 2 || ok.PercentUsed != 7 || ok.PowerOnHours != 7183 {
		t.Errorf("valid SMART values mis-parsed: media=%d pct=%d poh=%d (want 2,7,7183)",
			ok.MediaErrors, ok.PercentUsed, ok.PowerOnHours)
	}
}
