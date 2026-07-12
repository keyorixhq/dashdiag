package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCountDiskIssuesSMARTWearAndErrors verifies the disk summary counts a drive
// with NVMe media errors or high wear even when SMART overall still reports
// PASSED — otherwise a dying drive reads "Disk healthy" while `dsd health`
// (checkNVMe) raises CRIT/WARN on the same data.
func TestCountDiskIssuesSMARTWearAndErrors(t *testing.T) {
	cases := []struct {
		name  string
		smart *models.SMARTInfo
		want  int
	}{
		{"healthy drive", &models.SMARTInfo{Healthy: true, PercentUsed: 10}, 0},
		{"SMART failed", &models.SMARTInfo{Healthy: false}, 1},
		{"passed but media errors", &models.SMARTInfo{Healthy: true, MediaErrors: 3}, 1},
		{"passed but 90% worn", &models.SMARTInfo{Healthy: true, PercentUsed: 90}, 1},
		{"passed, 89% worn — under threshold", &models.SMARTInfo{Healthy: true, PercentUsed: 89}, 0},
		// Unreadable SMART (smartctl/nvme-cli absent, EBS/virtual disk): Error is set and
		// Healthy defaults to false. That is "couldn't measure", not a fault — it must NOT
		// count, or the summary raises a false WARN where dsd health reports INFO.
		{"SMART unreadable — tool absent", &models.SMARTInfo{Error: "smartctl not installed"}, 0},
		{"no SMART struct", nil, 0},
	}
	for _, c := range cases {
		info := &models.DiskInfo{Drives: []models.PhysicalDrive{{SMART: c.smart}}}
		if got := countDiskIssues(info, nil); got != c.want {
			t.Errorf("%s: countDiskIssues = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestDiskHasUnverifiedReads: a ZFS/LVM read-failure (commonly non-root) must be
// recognized so the summary won't claim a clean "Disk healthy" — mirroring dsd
// health's INFO. A read failure is NOT a counted concern (it's "couldn't measure").
func TestDiskHasUnverifiedReads(t *testing.T) {
	if diskHasUnverifiedReads(&models.DiskInfo{}, &models.LVMInfo{}) {
		t.Error("no read failures must report no unverified reads")
	}
	if !diskHasUnverifiedReads(&models.DiskInfo{ZFSListReadFailed: true}, nil) {
		t.Error("ZFSListReadFailed must count as an unverified read")
	}
	if !diskHasUnverifiedReads(nil, &models.LVMInfo{VGReadFailed: true}) {
		t.Error("LVM VGReadFailed must count as an unverified read")
	}
	// An unverified read must NOT inflate the concern tally (stays INFO, not WARN).
	if got := countDiskIssues(&models.DiskInfo{ZFSListReadFailed: true}, &models.LVMInfo{VGReadFailed: true}); got != 0 {
		t.Errorf("unverified reads must not be counted as concerns, got %d", got)
	}
}

// TestCountDiskIssuesFilesystemsBtrfsZFSAndLVM covers countDiskIssues'
// remaining branches not exercised by the SMART-only table above: filesystem
// capacity/inode thresholds (and the inherently-read-only skip), unhealthy
// Btrfs volumes, unhealthy/full/erroring ZFS pools, and degraded LVM RAID.
func TestCountDiskIssuesFilesystemsBtrfsZFSAndLVM(t *testing.T) {
	t.Parallel()

	// A filesystem over the warn threshold counts; one under does not; an
	// inherently read-only filesystem (squashfs) is always skipped regardless
	// of how full it is.
	fsInfo := &models.DiskInfo{Filesystems: []models.FilesystemInfo{
		{FSType: "ext4", UsedPct: 95},
		{FSType: "ext4", UsedPct: 10},
		{FSType: "squashfs", UsedPct: 100},
	}}
	if got := countDiskIssues(fsInfo, nil); got != 1 {
		t.Errorf("expected 1 issue (one over-threshold ext4, squashfs skipped), got %d", got)
	}

	inodeInfo := &models.DiskInfo{Filesystems: []models.FilesystemInfo{{FSType: "ext4", InodesUsedPct: 99}}}
	if got := countDiskIssues(inodeInfo, nil); got != 1 {
		t.Errorf("high inode usage should count as an issue, got %d", got)
	}

	btrfsInfo := &models.DiskInfo{BtrfsVolumes: []models.BtrfsVolume{
		{Status: "healthy"}, {Status: "degraded"},
	}}
	if got := countDiskIssues(btrfsInfo, nil); got != 1 {
		t.Errorf("one degraded Btrfs volume should count as 1 issue, got %d", got)
	}

	zfsInfo := &models.DiskInfo{ZFSPools: []models.ZFSPool{
		{State: "ONLINE", UsedPct: 10},
		{State: "DEGRADED", UsedPct: 10},
		{State: "ONLINE", UsedPct: 95},
		{State: "ONLINE", UsedPct: 10, ReadErrors: 1},
	}}
	if got := countDiskIssues(zfsInfo, nil); got != 3 {
		t.Errorf("degraded state + over-capacity + read errors should each count, got %d", got)
	}

	lvmInfo := &models.LVMInfo{RaidLVs: []models.LVMRaidLV{{Degraded: true}, {Degraded: false}}}
	if got := countDiskIssues(&models.DiskInfo{}, lvmInfo); got != 1 {
		t.Errorf("one degraded RAID LV should count as 1 issue, got %d", got)
	}
}

// TestCountSteamOSDiskIssues exercises every independent branch: nil (non-
// SteamOS host), a large shader cache, and broken bind mounts.
func TestCountSteamOSDiskIssues(t *testing.T) {
	if got := countSteamOSDiskIssues(nil); got != 0 {
		t.Errorf("nil SteamOS disk info should count 0 issues, got %d", got)
	}
	cases := []struct {
		name string
		d    models.SteamOSDisk
		want int
	}{
		{"clean", models.SteamOSDisk{}, 0},
		{"large shader cache", models.SteamOSDisk{ShaderCacheGB: 15}, 1},
		{"small shader cache not counted", models.SteamOSDisk{ShaderCacheGB: 5}, 0},
		{"one broken bind mount", models.SteamOSDisk{BindMounts: []models.SteamOSBindMount{{OK: false}}}, 1},
		{"intact bind mount not counted", models.SteamOSDisk{BindMounts: []models.SteamOSBindMount{{OK: true}}}, 0},
		{"cache plus two broken mounts", models.SteamOSDisk{
			ShaderCacheGB: 20,
			BindMounts:    []models.SteamOSBindMount{{OK: false}, {OK: false}, {OK: true}},
		}, 3},
	}
	for _, c := range cases {
		if got := countSteamOSDiskIssues(&c.d); got != c.want {
			t.Errorf("%s: countSteamOSDiskIssues = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestRunDisk exercises runDisk's real (read-only) collector wiring in
// --plain and --json mode (non-deep). Same real-I/O precedent as
// cpu_report_test.go / net_test.go's TestRunNet.
func TestRunDisk(t *testing.T) {
	plainCmd := newBareCloudCmd()
	plainCmd.SetContext(context.Background())
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runDisk(plainCmd, nil); err != nil {
			t.Fatalf("runDisk (plain): %v", err)
		}
	})
	if plainOut == "" {
		t.Error("runDisk (plain) produced no output")
	}

	jsonCmd := newBareCloudCmd()
	jsonCmd.SetContext(context.Background())
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runDisk(jsonCmd, nil); err != nil {
			t.Fatalf("runDisk (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, "{") {
		t.Errorf("json mode should emit JSON, got: %q", jsonOut)
	}

	// --deep switches to NewDiskDeepCollector (I/O rate sampling, two-sample
	// delta) — a distinct branch in runDisk from the plain/json cases above.
	// Shrink the real sample gap (Linux-only; no-op elsewhere) so the
	// two-sample requirement is still exercised without paying a real 1s
	// sleep in every CI run.
	defer shrinkDiskIOSampleGap()()

	deepCmd := newBareCloudCmd()
	deepCmd.SetContext(context.Background())
	_ = deepCmd.Flags().Set("plain", "true")
	_ = deepCmd.Flags().Set("deep", "true")
	deepOut := captureStdout(t, func() {
		if err := runDisk(deepCmd, nil); err != nil {
			t.Fatalf("runDisk (deep): %v", err)
		}
	})
	if deepOut == "" {
		t.Error("runDisk (deep) produced no output")
	}
}
