//go:build linux

package collectors

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── diskDetectType ───────────────────────────────────────────────────────────
//
// TestDiskDetectType_NVMe (parsers_round2_test.go) already covers the NVMe
// name-prefix branch. These cover the sysfs-rotational branches: SSD (0),
// HDD (1), and the "can't read rotational" fallback (SSD, don't assume HDD).

func TestDiskDetectType_SSD(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/block/sda/queue/rotational", []byte("0\n"))
	})
	if got := diskDetectType("sda"); got != models.DriveTypeSSD {
		t.Errorf("diskDetectType(sda, rotational=0) = %v, want SSD", got)
	}
}

func TestDiskDetectType_HDD(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/block/sda/queue/rotational", []byte("1\n"))
	})
	if got := diskDetectType("sda"); got != models.DriveTypeHDD {
		t.Errorf("diskDetectType(sda, rotational=1) = %v, want HDD", got)
	}
}

func TestDiskDetectType_RotationalUnreadable(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // queue/rotational never seeded
	if got := diskDetectType("sda"); got != models.DriveTypeSSD {
		t.Errorf("diskDetectType with unreadable rotational file = %v, want SSD fallback", got)
	}
}

// ── diskSizeGB ───────────────────────────────────────────────────────────────

func TestDiskSizeGB_Success(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// 1000000000 512-byte sectors ≈ 512GB
		b.PutFile("/sys/block/sda/size", []byte("1000000000\n"))
	})
	got := diskSizeGB("sda")
	want := 1000000000.0 * 512 / 1e9
	if got != want {
		t.Errorf("diskSizeGB = %v, want %v", got, want)
	}
}

func TestDiskSizeGB_Unreadable(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // size file never seeded
	if got := diskSizeGB("sda"); got != 0 {
		t.Errorf("diskSizeGB with unreadable size file = %v, want 0", got)
	}
}

func TestDiskSizeGB_Unparsable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/block/sda/size", []byte("not-a-number\n"))
	})
	if got := diskSizeGB("sda"); got != 0 {
		t.Errorf("diskSizeGB with unparsable size = %v, want 0", got)
	}
}

// ── diskModel ────────────────────────────────────────────────────────────────

func TestDiskModel_FirstPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/block/sda/device/model", []byte("Samsung SSD 980  \n"))
	})
	if got := diskModel("sda"); got != "Samsung SSD 980" {
		t.Errorf("diskModel = %q, want trimmed model string", got)
	}
}

func TestDiskModel_FallsBackToSecondPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// First candidate path absent, second (device/device/model) present.
		b.PutFile("/sys/block/sda/device/device/model", []byte("WDC WD2003FYYS\n"))
	})
	if got := diskModel("sda"); got != "WDC WD2003FYYS" {
		t.Errorf("diskModel = %q, want the second-path model", got)
	}
}

func TestDiskModel_NeitherPathReadable(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // neither model path seeded
	if got := diskModel("sda"); got != "" {
		t.Errorf("diskModel with no readable path = %q, want empty string", got)
	}
}

// ── enrichDeviceSizes ────────────────────────────────────────────────────────

func TestEnrichDeviceSizes_MixedResolvableAndUnresolvable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/sys/class/block/sda1", source.FileMeta{})
		b.PutFile("/sys/class/block/sda1/size", []byte("2000000\n")) // 2000000*512 bytes
		// /dev/does-not-exist is left unseeded — deviceSizeBytes must return ok=false.
	})
	filesystems := []models.FilesystemInfo{
		{Mount: "/", Device: "/dev/sda1"},
		{Mount: "/mnt/x", Device: "/dev/does-not-exist"},
	}
	enrichDeviceSizes(filesystems)

	wantGB := 2000000.0 * 512 / 1e9
	if filesystems[0].DeviceSizeGB != wantGB {
		t.Errorf("filesystems[0].DeviceSizeGB = %v, want %v", filesystems[0].DeviceSizeGB, wantGB)
	}
	if filesystems[1].DeviceSizeGB != 0 {
		t.Errorf("filesystems[1].DeviceSizeGB = %v, want 0 (unresolvable device left untouched)", filesystems[1].DeviceSizeGB)
	}
}

func TestEnrichDeviceSizes_EmptySlice(t *testing.T) {
	t.Parallel()
	// Must not panic on an empty/nil slice.
	enrichDeviceSizes(nil)
	enrichDeviceSizes([]models.FilesystemInfo{})
}

// ── collectLinuxExtras (via DiskCollector.Collect) ──────────────────────────
//
// TestDiskCollector_Collect_FiltersAndComputes (disk_linux_test.go) already
// exercises the container/no-drives path. These add: a live ZFS mount (so the
// zfsGate branch runs true), Deep mode (so the IOStats branch runs), and a
// non-container host with a physical drive present (so the SMART-collection
// loop body executes at least once, even though smartctl itself is absent).

// fakeStatfsLookPathSource layers BOTH a Statfs override and a Cached (lookPath)
// override on top of a Bundle-backed Replay — collectLinuxExtras' zfsGate()
// check (lookPath("zpool")) and DiskCollector.Collect's statfsToFS both need to
// be driven in the SAME test, and SetSource fully replaces rather than merges
// (see the withCombinedFixture GUARD comment in security_linux_source_test.go).
type fakeStatfsLookPathSource struct {
	*source.Replay
	statfs map[string]source.StatfsInfo
	found  map[string]bool
}

func (f *fakeStatfsLookPathSource) Statfs(path string) (source.StatfsInfo, error) {
	if v, ok := f.statfs[path]; ok {
		return v, nil
	}
	return f.Replay.Statfs(path)
}

func (f *fakeStatfsLookPathSource) Cached(key string, _ func() ([]byte, error)) ([]byte, error) {
	name := strings.TrimPrefix(key, "lookpath/")
	if f.found[name] {
		return []byte("/usr/sbin/" + name), nil
	}
	return nil, errNotFoundCVE
}

// TestCollectPhysicalDrives_ShortLineAndDedup guards two collectPhysicalDrives
// branches: a malformed /proc/partitions row with fewer than 4 fields is
// skipped, and a device name seen twice (can happen with certain partition
// table layouts) is deduplicated to a single entry.
func TestCollectPhysicalDrives_ShortLineAndDedup(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/mounts", []byte("/dev/sda1 / ext4 rw,relatime 0 0\n"))
		b.PutFile("/proc/partitions", []byte(
			"major minor  #blocks  name\n\n"+
				"   8        0   1000000\n"+ // too few fields — skipped
				"   8        0   1000000 sda\n"+
				"   8        0   1000000 sda\n")) // duplicate name — deduped
		b.PutFile("/sys/block/sda/queue/rotational", []byte("0\n"))
	})
	drives := collectPhysicalDrives()
	if len(drives) != 1 || drives[0].Name != "sda" {
		t.Errorf("drives = %+v, want exactly one deduplicated sda entry", drives)
	}
}

func TestCollectLinuxExtras_DeepModeWithZFSMount(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/proc/mounts", []byte(
		"/dev/sda1 / ext4 rw,relatime 0 0\n"+
			"tank /tank zfs rw,xattr,noacl 0 0\n"))
	b.PutFile("/proc/partitions", []byte(
		"major minor  #blocks  name\n\n"+
			"   8        0   1000000 sda\n"))
	b.PutFile("/sys/block/sda/queue/rotational", []byte("0\n"))
	b.PutCmdNotFound("zpool", []string{"list", "-H", "-o", "name,size,alloc,free,cap,frag,health"})
	prev := SetSource(&fakeStatfsLookPathSource{
		Replay: source.NewReplay(b),
		statfs: map[string]source.StatfsInfo{
			"/": {Bsize: 4096, Blocks: 1000, Bfree: 500, Bavail: 500, Files: 100, Ffree: 50},
		},
		found: map[string]bool{"zpool": true},
	})
	t.Cleanup(func() { SetSource(prev) })

	c := NewDiskDeepCollector()
	c.mountsPath = "/proc/mounts"
	c.ContainerCtx = platform.ContainerContext{InContainer: true} // still skip real SMART probes
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.DiskInfo)
	// zfsGate saw a live zfs mount but zpool isn't installed in this fixture —
	// collectZFSPools must report the read failure, not silently report zero
	// pools as if none existed.
	if !info.ZFSListReadFailed {
		t.Errorf("expected ZFSListReadFailed=true when zpool is absent despite a live zfs mount, got %+v", info)
	}
	// Deep mode must populate IOStats (possibly empty, but the field/branch
	// must have run) for whatever physical drives were discovered.
	if info.Drives == nil {
		t.Error("expected at least an empty (non-nil-producing) drives scan to have run")
	}
}

// TestCollectLinuxExtras_NonContainerSkipsWindowsAndRunsSMART covers the two
// collectLinuxExtras branches TestCollectLinuxExtras_DeepModeWithZFSMount's
// InContainer=true short-circuits away: an UNMOUNTED nvme drive on a dual-boot
// host gets the synthesized "not mounted (Windows/other OS)" sole-mount string
// (collectPhysicalDrives) and must be skipped before the virtual-disk/
// container check; a real (non-virtual, non-container) mounted SCSI drive
// must reach collectSMART (which itself degrades gracefully — "smartctl not
// installed" — without a real smartctl binary).
func TestCollectLinuxExtras_NonContainerSkipsWindowsAndRunsSMART(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/proc/mounts", []byte("/dev/sda1 / ext4 rw,relatime 0 0\n"))
	// sda1 is mounted (a real disk, reaches SMART); nvme0n1 has no /proc/mounts
	// entry at all, so collectPhysicalDrives assigns it the synthetic
	// "not mounted (Windows/other OS)" sole mount.
	b.PutFile("/proc/partitions", []byte(
		"major minor  #blocks  name\n\n"+
			"   8        0   1000000 sda\n"+
			"   8        1   1000000 sda1\n"+
			" 259        0   1000000 nvme0n1\n"))
	b.PutFile("/sys/block/sda/queue/rotational", []byte("0\n"))

	prev := SetSource(&fakeStatfsLookPathSource{
		Replay: source.NewReplay(b),
		statfs: map[string]source.StatfsInfo{
			"/": {Bsize: 4096, Blocks: 1000, Bfree: 500, Bavail: 500, Files: 100, Ffree: 50},
		},
		found: map[string]bool{}, // zpool/smartctl both absent — deterministic degrade
	})
	t.Cleanup(func() { SetSource(prev) })

	c := NewDiskCollector(platform.ContainerContext{InContainer: false})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.DiskInfo)

	var sda, nvme *models.PhysicalDrive
	for i := range info.Drives {
		switch info.Drives[i].Name {
		case "sda":
			sda = &info.Drives[i]
		case "nvme0n1":
			nvme = &info.Drives[i]
		}
	}
	if sda == nil || nvme == nil {
		t.Fatalf("expected both sda and nvme0n1 discovered, got %+v", info.Drives)
	}
	if len(nvme.Mounts) != 1 || !strings.Contains(nvme.Mounts[0], "Windows") {
		t.Fatalf("expected nvme0n1's sole mount to be the synthetic Windows placeholder, got %v", nvme.Mounts)
	}
	if nvme.SMART != nil {
		t.Error("a lone-Windows-mount drive must be skipped before collectSMART runs (SMART must stay nil)")
	}
	if sda.SMART == nil {
		t.Error("expected sda (real disk, non-container) to reach collectSMART and get a populated (degraded) SMARTInfo")
	}
	if sda.SMART != nil && sda.SMART.Error != "smartctl not installed" {
		t.Errorf("sda.SMART.Error = %q, want the no-smartctl degrade reason", sda.SMART.Error)
	}
}

// TestDiskCollector_ContextCancelledStopsMountScan guards internal-collectors-08-03:
// Collect's per-mount loop must observe ctx cancellation between iterations,
// not run to completion regardless of the caller's deadline. A large mount
// table (e.g. from many attacker-created FUSE mounts pointed at black-holed
// hosts) combined with statfsToFS's own unrelated 2s-per-mount internal
// timeout could otherwise blow well past the collector's declared Timeout().
// With an ALREADY-cancelled context, Collect must return promptly with an
// error and must not have processed any of the (many) mount entries.
func TestDiskCollector_ContextCancelledStopsMountScan(t *testing.T) {
	b := source.NewBundle()
	var mounts strings.Builder
	for i := 0; i < 50; i++ {
		mounts.WriteString("/dev/fake" + strconv.Itoa(i) + " /mnt/fake" + strconv.Itoa(i) + " ext4 rw,relatime 0 0\n")
	}
	b.PutFile("/proc/mounts", []byte(mounts.String()))
	prev := SetSource(&fakeStatfsLookPathSource{
		Replay: source.NewReplay(b),
		statfs: map[string]source.StatfsInfo{},
		found:  map[string]bool{},
	})
	t.Cleanup(func() { SetSource(prev) })

	c := NewDiskCollector(platform.ContainerContext{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before Collect ever starts its mount loop

	start := time.Now()
	raw, err := c.Collect(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from Collect with an already-cancelled context, got nil")
	}
	if elapsed > 500*time.Millisecond { // generous; statfsTimeout alone is 2s per stale mount
		t.Errorf("Collect took %v with an already-cancelled context — did not respect cancellation promptly", elapsed)
	}
	info, ok := raw.(*models.DiskInfo)
	if !ok || info == nil {
		t.Fatalf("expected a partial (possibly empty) *models.DiskInfo even on cancellation, got %#v", raw)
	}
	if len(info.Filesystems) != 0 {
		t.Errorf("expected zero filesystems processed (cancellation caught on the very first iteration), got %d", len(info.Filesystems))
	}
}
