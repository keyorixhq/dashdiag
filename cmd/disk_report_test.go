package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for disk.go's report renderers. Like pve.go, these take
// plain data structs with no live I/O, so captureStdout exercises them
// directly. NOTE: none of these use t.Parallel() — captureStdout swaps the
// package-global os.Stdout, so parallel tests corrupt each other's output
// (learned the hard way writing the pve.go equivalent of this file).

func TestDiskFmtGB(t *testing.T) {
	if got := diskFmtGB(500); got != "500GB" {
		t.Errorf("diskFmtGB(500) = %q, want 500GB", got)
	}
	if got := diskFmtGB(2000); got != "2TB" {
		t.Errorf("diskFmtGB(2000) = %q, want 2TB", got)
	}
}

func TestPrintSMARTLine(t *testing.T) {
	unreadable := captureStdout(t, func() { printSMARTLine(&models.SMARTInfo{Error: "smartctl not installed"}, output.ModePlain) })
	if !strings.Contains(unreadable, "smartctl not installed") {
		t.Errorf("an unreadable SMART must surface the error, got:\n%s", unreadable)
	}

	// A virtual/cloud volume answering PASSED with no real telemetry must not
	// render as a confident PASSED (mirrors dsd health's NVMeNoRealData).
	virtual := captureStdout(t, func() { printSMARTLine(&models.SMARTInfo{Healthy: true}, output.ModePlain) })
	if strings.Contains(virtual, "PASSED") {
		t.Errorf("no-telemetry SMART must not claim PASSED, got:\n%s", virtual)
	}
	if !strings.Contains(virtual, "no real telemetry") {
		t.Errorf("no-telemetry SMART should say so, got:\n%s", virtual)
	}

	failed := captureStdout(t, func() { printSMARTLine(&models.SMARTInfo{Healthy: false, Temperature: 40}, output.ModePlain) })
	if !strings.Contains(failed, "CRIT") || !strings.Contains(failed, "FAILED") {
		t.Errorf("Healthy=false should render CRIT/FAILED, got:\n%s", failed)
	}

	// A drive still reporting PASSED but 90%+ worn must not read as a clean OK —
	// the #372-class wear/media-error gate.
	worn := captureStdout(t, func() {
		printSMARTLine(&models.SMARTInfo{Healthy: true, Temperature: 40, PercentUsed: 95}, output.ModePlain)
	})
	if !strings.Contains(worn, "WARN") {
		t.Errorf("PASSED but 95%% worn must render WARN, got:\n%s", worn)
	}

	mediaErrs := captureStdout(t, func() {
		printSMARTLine(&models.SMARTInfo{Healthy: true, Temperature: 40, MediaErrors: 3}, output.ModePlain)
	})
	if !strings.Contains(mediaErrs, "WARN") {
		t.Errorf("PASSED but with media errors must render WARN, got:\n%s", mediaErrs)
	}

	// PowerOnHours > 0 emits a second summary line with power-on/cycle stats.
	powerOn := captureStdout(t, func() {
		printSMARTLine(&models.SMARTInfo{Healthy: true, PowerOnHours: 240, UnsafeShutdowns: 2, PowerCycles: 50}, output.ModePlain)
	})
	if !strings.Contains(powerOn, "power-on: 240h (10 days)") || !strings.Contains(powerOn, "shutdowns: 2") || !strings.Contains(powerOn, "cycles: 50") {
		t.Errorf("PowerOnHours > 0 should render the power-on/shutdowns/cycles line, got:\n%s", powerOn)
	}
}

// TestPrintSMARTLine_SanitizesError guards Finding: internal-collectors-24-02.
// s.Error is built from smartctl's JSON open_error/OpenError fields — drive-
// reported text a hostile device could use to inject terminal control bytes.
func TestPrintSMARTLine_SanitizesError(t *testing.T) {
	out := captureStdout(t, func() {
		printSMARTLine(&models.SMARTInfo{Error: "smartctl: \x1b[31mFAKE\x1b[0m open failed"}, output.ModePlain)
	})
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("SMART error output contains a raw ESC byte, got:\n%q", out)
	}
	if !strings.Contains(out, "FAKE") || !strings.Contains(out, "open failed") {
		t.Errorf("printable text around the escape sequence must survive sanitization, got:\n%q", out)
	}
}

func TestPrintDiskDrives(t *testing.T) {
	if out := captureStdout(t, func() { printDiskDrives(&models.DiskInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("no drives should print nothing, got:\n%s", out)
	}

	info := &models.DiskInfo{Drives: []models.PhysicalDrive{
		{Name: "nvme0n1", SizeGB: 500, Model: "Samsung 980", SMART: &models.SMARTInfo{Healthy: true, Temperature: 35}},
	}}
	out := captureStdout(t, func() { printDiskDrives(info, output.ModePlain) })
	if !strings.Contains(out, "nvme0n1") || !strings.Contains(out, "Samsung 980") {
		t.Errorf("drive name/model should be listed, got:\n%s", out)
	}
	if !strings.Contains(out, "SMART") {
		t.Errorf("a drive with SMART data should render the SMART sub-line, got:\n%s", out)
	}
}

// TestPrintDiskDrives_SanitizesModel guards Finding: internal-collectors-24-02.
// d.Model comes straight from sysfs (`model` file) / smartctl JSON — a
// hostile device, USB drive, or virtualization backend can embed terminal
// control/escape bytes in it.
func TestPrintDiskDrives_SanitizesModel(t *testing.T) {
	info := &models.DiskInfo{Drives: []models.PhysicalDrive{
		{Name: "sda", SizeGB: 100, Model: "\x1b[8mHIDDEN\x1b[0m Drive"},
	}}
	out := captureStdout(t, func() { printDiskDrives(info, output.ModePlain) })
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("drive model output contains a raw ESC byte, got:\n%q", out)
	}
	if !strings.Contains(out, "HIDDEN") || !strings.Contains(out, "Drive") {
		t.Errorf("printable text around the escape sequence must survive sanitization, got:\n%q", out)
	}
}

func TestPrintDiskBtrfs(t *testing.T) {
	if out := captureStdout(t, func() { printDiskBtrfs(&models.DiskInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("no btrfs volumes should print nothing, got:\n%s", out)
	}

	degraded := captureStdout(t, func() {
		printDiskBtrfs(&models.DiskInfo{BtrfsVolumes: []models.BtrfsVolume{
			{MountPoint: "/", Status: "degraded", MissingDevs: 1, TotalDevices: 2,
				Devices: []models.BtrfsDev{{DevID: 1, Missing: true}}},
		}}, output.ModePlain)
	})
	if !strings.Contains(degraded, "CRIT") || !strings.Contains(degraded, "DEGRADED") {
		t.Errorf("a degraded volume must render CRIT/DEGRADED, got:\n%s", degraded)
	}
	if !strings.Contains(degraded, "<missing disk>") {
		t.Errorf("a missing device should be labeled, got:\n%s", degraded)
	}

	deviceErrs := captureStdout(t, func() {
		printDiskBtrfs(&models.DiskInfo{BtrfsVolumes: []models.BtrfsVolume{
			{MountPoint: "/", Status: "errors", TotalDevices: 1,
				Devices: []models.BtrfsDev{{DevID: 1, Path: "/dev/sda1", CorruptErrs: 2}}},
		}}, output.ModePlain)
	})
	if !strings.Contains(deviceErrs, "WARN") {
		t.Errorf("a volume with device errors must render WARN, got:\n%s", deviceErrs)
	}
	if !strings.Contains(deviceErrs, "corrupt:2") {
		t.Errorf("per-device error counters should be shown, got:\n%s", deviceErrs)
	}
}

func TestPrintDiskZFS(t *testing.T) {
	// zpool list errored (non-root): must surface "could not verify", never silent OK.
	unreadable := captureStdout(t, func() {
		printDiskZFS(&models.DiskInfo{ZFSListReadFailed: true}, output.ModePlain)
	})
	if !strings.Contains(unreadable, "could not be listed") {
		t.Errorf("a failed zpool list read must be surfaced, got:\n%s", unreadable)
	}

	// No ZFS at all: genuinely silent.
	if out := captureStdout(t, func() { printDiskZFS(&models.DiskInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("no ZFS at all should print nothing, got:\n%s", out)
	}

	degraded := captureStdout(t, func() {
		printDiskZFS(&models.DiskInfo{ZFSPools: []models.ZFSPool{{Name: "tank", State: "DEGRADED"}}}, output.ModePlain)
	})
	if !strings.Contains(degraded, "CRIT") {
		t.Errorf("a DEGRADED pool must render CRIT, got:\n%s", degraded)
	}

	fullPool := captureStdout(t, func() {
		printDiskZFS(&models.DiskInfo{ZFSPools: []models.ZFSPool{{Name: "tank", State: "ONLINE", UsedPct: 95}}}, output.ModePlain)
	})
	if !strings.Contains(fullPool, "CRIT") {
		t.Errorf("an ONLINE pool at 95%% used must still render CRIT, got:\n%s", fullPool)
	}

	neverScrubbed := captureStdout(t, func() {
		printDiskZFS(&models.DiskInfo{ZFSPools: []models.ZFSPool{{Name: "tank", State: "ONLINE", ScrubAgeDays: -1}}}, output.ModePlain)
	})
	if !strings.Contains(neverScrubbed, "never scrubbed") {
		t.Errorf("ScrubAgeDays -1 should say never scrubbed, got:\n%s", neverScrubbed)
	}

	// ONLINE pool in the WARN band (below CRIT threshold): distinct icon branch
	// from both the healthy and CRIT-full cases above.
	warnPool := captureStdout(t, func() {
		printDiskZFS(&models.DiskInfo{ZFSPools: []models.ZFSPool{{Name: "tank", State: "ONLINE", UsedPct: 85}}}, output.ModePlain)
	})
	if !strings.Contains(warnPool, "WARN") {
		t.Errorf("an ONLINE pool in the WARN band must render WARN, got:\n%s", warnPool)
	}

	// Non-zero read/write/checksum error counters must be surfaced inline.
	poolErrs := captureStdout(t, func() {
		printDiskZFS(&models.DiskInfo{ZFSPools: []models.ZFSPool{
			{Name: "tank", State: "ONLINE", ReadErrors: 2, WriteErrors: 1, CksumErrors: 3},
		}}, output.ModePlain)
	})
	if !strings.Contains(poolErrs, "R:2 W:1 C:3") {
		t.Errorf("pool read/write/checksum error counters should be shown, got:\n%s", poolErrs)
	}

	// A scrub older than 30 days (but still >= 0, i.e. one has run) must be
	// noted as a plain informational aging line, not "never scrubbed".
	overdueScrub := captureStdout(t, func() {
		printDiskZFS(&models.DiskInfo{ZFSPools: []models.ZFSPool{{Name: "tank", State: "ONLINE", ScrubAgeDays: 45}}}, output.ModePlain)
	})
	if !strings.Contains(overdueScrub, "last scrub 45d ago") {
		t.Errorf("an overdue scrub should show its age, got:\n%s", overdueScrub)
	}
}

func TestPrintDiskFilesystems(t *testing.T) {
	// A packed-full read-only image filesystem (squashfs/iso9660/etc.) must NEVER
	// render a fault icon even at 100% used — that's normal by design (#382).
	imageFS := captureStdout(t, func() {
		printDiskFilesystems(&models.DiskInfo{Filesystems: []models.FilesystemInfo{
			{Mount: "/snap/core/1", FSType: "squashfs", TotalGB: 1, UsedGB: 1, UsedPct: 100},
		}}, output.ModePlain)
	})
	if strings.Contains(imageFS, "CRIT") || strings.Contains(imageFS, "WARN") {
		t.Errorf("a 100%%-full squashfs must not render a fault icon, got:\n%s", imageFS)
	}

	fullFS := captureStdout(t, func() {
		printDiskFilesystems(&models.DiskInfo{Filesystems: []models.FilesystemInfo{
			{Mount: "/", FSType: "ext4", TotalGB: 100, UsedGB: 95, UsedPct: 95},
		}}, output.ModePlain)
	})
	if !strings.Contains(fullFS, "CRIT") {
		t.Errorf("a normal ext4 fs at 95%% used must render CRIT, got:\n%s", fullFS)
	}

	inodes := captureStdout(t, func() {
		printDiskFilesystems(&models.DiskInfo{Filesystems: []models.FilesystemInfo{
			{Mount: "/", FSType: "ext4", TotalGB: 100, UsedGB: 10, UsedPct: 10, InodesUsedPct: 95},
		}}, output.ModePlain)
	})
	if !strings.Contains(inodes, "inodes at 95%") {
		t.Errorf("high inode usage should be called out separately from space usage, got:\n%s", inodes)
	}

	// A zero-size filesystem (e.g. a pseudo-fs with no real capacity) must be
	// skipped entirely rather than rendered as a 0/0 row.
	zeroSize := captureStdout(t, func() {
		printDiskFilesystems(&models.DiskInfo{Filesystems: []models.FilesystemInfo{
			{Mount: "/proc", FSType: "proc", TotalGB: 0},
			{Mount: "/", FSType: "ext4", TotalGB: 100, UsedGB: 10, UsedPct: 10},
		}}, output.ModePlain)
	})
	if strings.Contains(zeroSize, "/proc") {
		t.Errorf("a zero-size filesystem should be skipped, got:\n%s", zeroSize)
	}

	// WARN band: below CRIT but at/above WARN — distinct icon branch from
	// both the CRIT (95%) and healthy (10%) cases above.
	warnFS := captureStdout(t, func() {
		printDiskFilesystems(&models.DiskInfo{Filesystems: []models.FilesystemInfo{
			{Mount: "/", FSType: "ext4", TotalGB: 100, UsedGB: 85, UsedPct: 85},
		}}, output.ModePlain)
	})
	if !strings.Contains(warnFS, "WARN") {
		t.Errorf("a filesystem in the WARN band must render WARN, got:\n%s", warnFS)
	}
}

func TestPrintDiskIO(t *testing.T) {
	if out := captureStdout(t, func() { printDiskIO(&models.DiskInfo{}) }); out != "" {
		t.Errorf("no I/O stats should print nothing, got:\n%s", out)
	}
	out := captureStdout(t, func() {
		printDiskIO(&models.DiskInfo{IOStats: []models.DiskIOStat{{Device: "nvme0n1", ReadMBs: 12.5, WriteMBs: 3.1}}})
	})
	if !strings.Contains(out, "nvme0n1") {
		t.Errorf("I/O stats should list the device, got:\n%s", out)
	}
}

func TestPrintDiskSteamOS(t *testing.T) {
	if out := captureStdout(t, func() { printDiskSteamOS(&models.DiskInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("nil SteamOS section should print nothing, got:\n%s", out)
	}

	overCache := captureStdout(t, func() {
		printDiskSteamOS(&models.DiskInfo{SteamOS: &models.SteamOSDisk{ShaderCacheGB: 35}}, output.ModePlain)
	})
	if !strings.Contains(overCache, "CRIT") {
		t.Errorf("35GB shader cache should render CRIT, got:\n%s", overCache)
	}

	brokenMount := captureStdout(t, func() {
		printDiskSteamOS(&models.DiskInfo{SteamOS: &models.SteamOSDisk{
			BindMounts: []models.SteamOSBindMount{{Path: "/opt", Target: "/home/.steamos/offload/opt", OK: false}},
		}}, output.ModePlain)
	})
	if !strings.Contains(brokenMount, "broken") {
		t.Errorf("a broken bind mount should be flagged, got:\n%s", brokenMount)
	}

	warnCache := captureStdout(t, func() {
		printDiskSteamOS(&models.DiskInfo{SteamOS: &models.SteamOSDisk{ShaderCacheGB: 15}}, output.ModePlain)
	})
	if !strings.Contains(warnCache, "WARN") {
		t.Errorf("15GB shader cache (10-30GB band) should render WARN, got:\n%s", warnCache)
	}

	okCache := captureStdout(t, func() {
		printDiskSteamOS(&models.DiskInfo{SteamOS: &models.SteamOSDisk{ShaderCacheGB: 2}}, output.ModePlain)
	})
	if !strings.Contains(okCache, "OK") {
		t.Errorf("2GB shader cache should render OK, got:\n%s", okCache)
	}

	intactMount := captureStdout(t, func() {
		printDiskSteamOS(&models.DiskInfo{SteamOS: &models.SteamOSDisk{
			BindMounts: []models.SteamOSBindMount{{Path: "/opt", Target: "/home/.steamos/offload/opt", OK: true}},
		}}, output.ModePlain)
	})
	if !strings.Contains(intactMount, "intact") {
		t.Errorf("an OK bind mount should render as intact, got:\n%s", intactMount)
	}
}

func TestPrintDiskLVM(t *testing.T) {
	if out := captureStdout(t, func() { printDiskLVM(nil, output.ModePlain) }); out != "" {
		t.Errorf("nil LVM info should print nothing, got:\n%s", out)
	}

	// vgs/pvs/lvs errored (non-root): must surface "could not verify".
	unreadable := captureStdout(t, func() {
		printDiskLVM(&models.LVMInfo{VGReadFailed: true}, output.ModePlain)
	})
	if !strings.Contains(unreadable, "could not be read") {
		t.Errorf("a failed LVM read must be surfaced, got:\n%s", unreadable)
	}

	// Genuinely no LVM at all: silent.
	if out := captureStdout(t, func() { printDiskLVM(&models.LVMInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("no LVM at all should print nothing, got:\n%s", out)
	}

	// The outer presence gate itself (`lvs --version`) couldn't confirm lvm2
	// is absent — must disclose, not silently fall through to the "no LVM at
	// all" case above (VGs/ThinPools/etc are empty for a different reason:
	// nothing was queried, not genuine absence).
	presenceFailed := captureStdout(t, func() {
		printDiskLVM(&models.LVMInfo{PresenceReadFailed: true}, output.ModePlain)
	})
	if !strings.Contains(presenceFailed, "could not confirm whether LVM is installed") {
		t.Errorf("a failed presence check must be disclosed, got:\n%s", presenceFailed)
	}

	missingPV := captureStdout(t, func() {
		printDiskLVM(&models.LVMInfo{VGs: []models.LVMVG{{Name: "pve", MissingPVs: 1}}}, output.ModePlain)
	})
	if !strings.Contains(missingPV, "data at risk") {
		t.Errorf("a VG with a missing PV must warn of data risk, got:\n%s", missingPV)
	}

	thinBacked := captureStdout(t, func() {
		printDiskLVM(&models.LVMInfo{
			VGs:       []models.LVMVG{{Name: "pve", FreePct: 2}}, // ~98% full
			ThinPools: []models.LVMThinPool{{Name: "data", VG: "pve", DataPct: 50}},
		}, output.ModePlain)
	})
	if !strings.Contains(thinBacked, "thin-pool backed") {
		t.Errorf("a thin-pool-backed VG must not be scored as a full disk, got:\n%s", thinBacked)
	}

	thinPoolCrit := captureStdout(t, func() {
		printDiskLVM(&models.LVMInfo{ThinPools: []models.LVMThinPool{{Name: "data", VG: "pve", DataPct: 95}}}, output.ModePlain)
	})
	if !strings.Contains(thinPoolCrit, "CRIT") {
		t.Errorf("a thin pool at 95%% data must render CRIT, got:\n%s", thinPoolCrit)
	}

	// WARN band: below CRIT (90) but at/above WARN (80) — distinct icon branch.
	thinPoolWarn := captureStdout(t, func() {
		printDiskLVM(&models.LVMInfo{ThinPools: []models.LVMThinPool{{Name: "data", VG: "pve", DataPct: 85}}}, output.ModePlain)
	})
	if !strings.Contains(thinPoolWarn, "WARN") {
		t.Errorf("a thin pool in the WARN band must render WARN, got:\n%s", thinPoolWarn)
	}

	snapshotCrit := captureStdout(t, func() {
		printDiskLVM(&models.LVMInfo{Snapshots: []models.LVMSnapshot{{Name: "snap0", VG: "pve", Origin: "root", DataPct: 99}}}, output.ModePlain)
	})
	if !strings.Contains(snapshotCrit, "CRIT") {
		t.Errorf("a snapshot at 99%% COW fill must render CRIT, got:\n%s", snapshotCrit)
	}

	// WARN band: below CRIT (95) but at/above WARN (80) for snapshots.
	snapshotWarn := captureStdout(t, func() {
		printDiskLVM(&models.LVMInfo{Snapshots: []models.LVMSnapshot{{Name: "snap0", VG: "pve", Origin: "root", DataPct: 85}}}, output.ModePlain)
	})
	if !strings.Contains(snapshotWarn, "WARN") {
		t.Errorf("a snapshot in the WARN band must render WARN, got:\n%s", snapshotWarn)
	}

	raidDegraded := captureStdout(t, func() {
		printDiskLVM(&models.LVMInfo{RaidLVs: []models.LVMRaidLV{{Name: "lv0", VG: "pve", Degraded: true}}}, output.ModePlain)
	})
	if !strings.Contains(raidDegraded, "DEGRADED") {
		t.Errorf("a degraded RAID LV must say so, got:\n%s", raidDegraded)
	}
}

// TestPrintDiskReportSummary pins the three-way summary verdict: concerns found
// (WARN), unverified reads with no concerns (INFO, must not read healthy — the
// false-OK dsd health avoids), and genuinely healthy.
func TestPrintDiskReportSummary(t *testing.T) {
	healthy := captureStdout(t, func() {
		printDiskReport(&models.DiskInfo{}, nil, output.ModePlain, 0, false)
	})
	if !strings.Contains(healthy, "Disk healthy") {
		t.Errorf("no issues, no unverified reads should read healthy, got:\n%s", healthy)
	}

	unverified := captureStdout(t, func() {
		printDiskReport(&models.DiskInfo{ZFSListReadFailed: true}, nil, output.ModePlain, 0, false)
	})
	if strings.Contains(unverified, "Disk healthy") {
		t.Errorf("an unverified read must not claim healthy, got:\n%s", unverified)
	}
	if !strings.Contains(unverified, "could not be verified") {
		t.Errorf("an unverified read should say so in the summary, got:\n%s", unverified)
	}

	concern := captureStdout(t, func() {
		printDiskReport(&models.DiskInfo{Filesystems: []models.FilesystemInfo{
			{Mount: "/", FSType: "ext4", TotalGB: 100, UsedGB: 95, UsedPct: 95},
		}}, nil, output.ModePlain, 0, false)
	})
	if !strings.Contains(concern, "concern(s) found") {
		t.Errorf("a full filesystem should surface as a concern, got:\n%s", concern)
	}
}
