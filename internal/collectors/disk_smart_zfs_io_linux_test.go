//go:build linux

package collectors

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestCollectSMART_NoTool guards the "smartctl not installed" early-out: no
// health/attribute commands should even be attempted.
func TestCollectSMART_NoTool(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("smartctl", nil)
	})
	got := collectSMART(context.Background(), "sda")
	if got.Device != "/dev/sda" {
		t.Errorf("Device = %q, want /dev/sda", got.Device)
	}
	if got.Error != "smartctl not installed" {
		t.Errorf("Error = %q, want %q", got.Error, "smartctl not installed")
	}
}

// TestCollectSMART_HealthyWithAttributes guards the full happy path: smartctl
// -H reports PASSED (exit 0), smartctl -A is parsed for wear/spare/temp.
func TestCollectSMART_HealthyWithAttributes(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/smartctl": []byte("/usr/sbin/smartctl"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"-H", "/dev/nvme0n1"},
			"SMART overall-health self-assessment test result: PASSED\n", 0)
		b.PutCmd("smartctl", []string{"-A", "/dev/nvme0n1"},
			"Percentage Used:                     3%\n"+
				"Available Spare:                     100%\n"+
				"Temperature:                         35 Celsius\n"+
				"Media and Data Integrity Errors:     0\n"+
				"Power On Hours:                      1200\n",
			0)
	})
	got := collectSMART(context.Background(), "nvme0n1")
	if !got.Healthy {
		t.Error("expected Healthy=true for a PASSED verdict")
	}
	if got.Error != "" {
		t.Errorf("Error = %q, want empty", got.Error)
	}
	if got.PercentUsed != 3 {
		t.Errorf("PercentUsed = %d, want 3", got.PercentUsed)
	}
	if got.AvailableSpare != 100 {
		t.Errorf("AvailableSpare = %d, want 100", got.AvailableSpare)
	}
	if got.Temperature != 35 {
		t.Errorf("Temperature = %d, want 35", got.Temperature)
	}
	if got.PowerOnHours != 1200 {
		t.Errorf("PowerOnHours = %d, want 1200", got.PowerOnHours)
	}
}

// TestCollectSMART_FailingDriveNonZeroExit guards the documented regression:
// smartctl -H exits NON-ZERO when a drive is FAILING but still prints a valid
// verdict on stdout — the verdict must still be parsed, not dropped as an
// error (the exact bug fixed in the doc comment above collectSMART).
func TestCollectSMART_FailingDriveNonZeroExit(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/smartctl": []byte("/usr/sbin/smartctl"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"-H", "/dev/sda"},
			"SMART overall-health self-assessment test result: FAILED!\n", 1)
		b.PutCmd("smartctl", []string{"-A", "/dev/sda"}, "", 1)
	})
	got := collectSMART(context.Background(), "sda")
	if got.Healthy {
		t.Error("expected Healthy=false for a FAILED verdict")
	}
	if got.Error != "" {
		t.Errorf("Error = %q, want empty (a parsed verdict is not an error, even on non-zero exit)", got.Error)
	}
}

// TestCollectSMART_NoVerdictReported guards the genuine-failure branch: when
// smartctl errors AND prints no recognizable verdict line, Error must be set
// so the caller doesn't silently treat the drive as unmeasured-but-OK.
func TestCollectSMART_NoVerdictReported(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/smartctl": []byte("/usr/sbin/smartctl"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"-H", "/dev/sdz"}, "", 2)
	})
	got := collectSMART(context.Background(), "sdz")
	if got.Healthy {
		t.Error("expected Healthy=false (zero value) when no verdict is present")
	}
	if got.Error == "" {
		t.Error("expected a non-empty Error when smartctl fails with no parseable verdict")
	}
}

// TestCollectSMART_NoVerdictButExitZero guards the "no err, but also no
// recognizable health line" branch — must report "no health status reported".
func TestCollectSMART_NoVerdictButExitZero(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/smartctl": []byte("/usr/sbin/smartctl"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"-H", "/dev/sdy"}, "some unrelated banner output\n", 0)
	})
	got := collectSMART(context.Background(), "sdy")
	if got.Error != "smartctl: no health status reported" {
		t.Errorf("Error = %q, want %q", got.Error, "smartctl: no health status reported")
	}
}

// TestCollectZFSPools_ListOnly guards the pool-row parse from `zpool list`
// plus the per-pool `zpool status` merge for scrub age and vdev errors.
func TestCollectZFSPools_ListOnly(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/zpool": []byte("/sbin/zpool"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("zpool", []string{"list", "-H", "-o", "name,size,alloc,free,cap,frag,health"},
			"tank\t1T\t400G\t600G\t40%\t5%\tONLINE\n", 0)
		b.PutCmd("zpool", []string{"status", "tank"},
			"  pool: tank\n state: ONLINE\n  scan: scrub repaired 0B in 00:04:30 with 0 errors on Sun Jun  1 03:28:31 2020\n"+
				"config:\n\n\tNAME        STATE     READ WRITE CKSUM\n\ttank        ONLINE       0     0     0\n\nerrors: No known data errors",
			0)
	})
	pools, listFailed := collectZFSPools(context.Background())
	if listFailed {
		t.Fatal("listReadFailed = true, want false")
	}
	if len(pools) != 1 {
		t.Fatalf("expected 1 pool, got %d: %+v", len(pools), pools)
	}
	p := pools[0]
	if p.Name != "tank" || p.State != "ONLINE" {
		t.Errorf("unexpected pool identity: %+v", p)
	}
	if p.StatusReadFailed {
		t.Error("StatusReadFailed = true, want false (zpool status succeeded)")
	}
	if p.ScrubAgeDays < 1000 {
		t.Errorf("ScrubAgeDays = %d, want a large positive (scrub date is in 2020)", p.ScrubAgeDays)
	}
	if p.ReadErrors != 0 || p.WriteErrors != 0 || p.CksumErrors != 0 {
		t.Errorf("expected zero vdev errors, got read=%d write=%d cksum=%d", p.ReadErrors, p.WriteErrors, p.CksumErrors)
	}
}

// TestCollectZFSPools_ListFails guards the "zpool list itself failed" branch:
// must return listReadFailed=true, not an empty-but-clean pool list — the
// gate caller already confirmed a live ZFS mount, so this is a real
// "couldn't verify", not "no pools".
func TestCollectZFSPools_ListFails(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/zpool": []byte("/sbin/zpool"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("zpool", []string{"list", "-H", "-o", "name,size,alloc,free,cap,frag,health"}, "", 1)
	})
	pools, listFailed := collectZFSPools(context.Background())
	if !listFailed {
		t.Error("listReadFailed = false, want true")
	}
	if len(pools) != 0 {
		t.Errorf("expected no pools when list read failed, got %+v", pools)
	}
}

// TestCollectZFSPools_StatusFails guards the per-pool "status read failed"
// branch: StatusReadFailed must be set so the zero-value ScrubAgeDays/error
// counts aren't misread as "clean" — the pool's list-derived fields (Name,
// State, UsedPct, FragPct, FreeGB) are still populated from `zpool list`.
func TestCollectZFSPools_StatusFails(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/zpool": []byte("/sbin/zpool"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("zpool", []string{"list", "-H", "-o", "name,size,alloc,free,cap,frag,health"},
			"tank\t1T\t400G\t600G\t40%\t5%\tONLINE\n", 0)
		b.PutCmd("zpool", []string{"status", "tank"}, "", 1)
	})
	pools, listFailed := collectZFSPools(context.Background())
	if listFailed {
		t.Fatal("listReadFailed = true, want false")
	}
	if len(pools) != 1 {
		t.Fatalf("expected 1 pool, got %d", len(pools))
	}
	if !pools[0].StatusReadFailed {
		t.Error("StatusReadFailed = false, want true (zpool status failed)")
	}
	if pools[0].ScrubAgeDays != -1 {
		t.Errorf("ScrubAgeDays = %d, want -1 (default, status read failed)", pools[0].ScrubAgeDays)
	}
}

// TestCollectDiskIO guards the two-sample-delta /proc/diskstats read: a
// static fixture returns identical stats on both samples, so the delta for a
// present device must be exactly zero (not negative-clamped garbage), and a
// drive absent from /proc/diskstats must still produce a zero-value entry
// rather than being skipped (len(stats) == len(drives) always).
func TestCollectDiskIO(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// fields: major minor name reads_completed reads_merged sectors_read
		// ms_reading writes_completed writes_merged sectors_written ms_writing
		// ios_in_progress ms_ios weighted_ms_ios
		b.PutFile("/proc/diskstats", []byte(
			"   8       0 sda 100 5 20000 10 200 20 40000 30 0 40 60\n"+
				"   8      16 sdb 50 2 10000 5 100 10 20000 15 0 20 30\n",
		))
	})
	drives := []models.PhysicalDrive{{Name: "sda"}, {Name: "sdb"}, {Name: "nvme0n1"}}
	stats := collectDiskIO(drives)
	if len(stats) != len(drives) {
		t.Fatalf("expected one DiskIOStat per drive (%d), got %d: %+v", len(drives), len(stats), stats)
	}
	for _, s := range stats {
		if s.ReadMBs != 0 || s.WriteMBs != 0 {
			t.Errorf("device %q: static fixture (identical before/after) must yield a zero delta, got read=%v write=%v", s.Device, s.ReadMBs, s.WriteMBs)
		}
	}
	// nvme0n1 is absent from /proc/diskstats — must still produce an entry
	// (zero-value), never be dropped.
	found := false
	for _, s := range stats {
		if s.Device == "nvme0n1" {
			found = true
		}
	}
	if !found {
		t.Error("expected a zero-value entry for a drive absent from /proc/diskstats, got none")
	}
}

// TestCollectDiskIO_ShortLineSkipped guards the len(fields)<14 skip: a
// malformed/truncated /proc/diskstats row must not crash strconv.ParseInt on
// missing fields and must not contaminate the well-formed rows around it.
func TestCollectDiskIO_ShortLineSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/diskstats", []byte(
			"   8       0 sda\n"+ // too few fields — skipped
				"   8       0 sda 100 5 20000 10 200 20 40000 30 0 40 60\n",
		))
	})
	drives := []models.PhysicalDrive{{Name: "sda"}}
	stats := collectDiskIO(drives)
	if len(stats) != 1 || stats[0].Device != "sda" {
		t.Fatalf("stats = %+v, want one sda entry (short line skipped, not crashed)", stats)
	}
}

// TestCollectDiskIO_ScanTooLong guards the scanner.Err() branch: a
// /proc/diskstats blob with a single line exceeding bufio.Scanner's default
// 64KB token limit must return the partial map read so far (per the
// function's own doc comment), not propagate the scan error to the caller.
func TestCollectDiskIO_ScanTooLong(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		huge := strings.Repeat("x", 100*1024)
		b.PutFile("/proc/diskstats", []byte(
			"   8       0 sda 100 5 20000 10 200 20 40000 30 0 40 60\n"+huge+"\n"))
	})
	drives := []models.PhysicalDrive{{Name: "sda"}}
	stats := collectDiskIO(drives)
	if len(stats) != 1 || stats[0].Device != "sda" {
		t.Fatalf("stats = %+v, want the partial (pre-overflow) read preserved", stats)
	}
}

// TestCollectDiskIO_NoDiskstatsFile guards the "openFile fails entirely"
// branch on both samples — must degrade to zero-value entries per drive, not
// panic or return a shorter slice.
func TestCollectDiskIO_NoDiskstatsFile(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // /proc/diskstats never seeded
	drives := []models.PhysicalDrive{{Name: "sda"}}
	stats := collectDiskIO(drives)
	if len(stats) != 1 {
		t.Fatalf("expected 1 entry, got %d: %+v", len(stats), stats)
	}
	if stats[0].ReadMBs != 0 || stats[0].WriteMBs != 0 {
		t.Errorf("expected zero-value stat when /proc/diskstats is unreadable, got %+v", stats[0])
	}
}

// decreasingDiskstatsSource returns a lower sector count on the SECOND
// /proc/diskstats read than the first, simulating a counter rollover/reset
// (or a garbled capture) so collectDiskIO's negative-delta clamp fires. All
// other Source methods delegate to an embedded Replay over an empty Bundle.
type decreasingDiskstatsSource struct {
	source.Source
	calls int
}

func (d *decreasingDiskstatsSource) ReadFile(path string) ([]byte, error) {
	if path != "/proc/diskstats" {
		return nil, errors.New("unexpected path in test fake: " + path)
	}
	d.calls++
	if d.calls == 1 {
		// fields: major minor name reads_completed reads_merged sectors_read
		// ms_reading writes_completed writes_merged sectors_written ms_writing
		// ios_in_progress ms_ios weighted_ms_ios
		return []byte("   8       0 sda 100 5 20000 10 200 20 40000 30 0 40 60\n"), nil
	}
	// Second sample: sector counts dropped below the first sample's — must
	// clamp to zero, never a negative MB delta.
	return []byte("   8       0 sda 100 5 10000 10 200 20 20000 30 0 40 60\n"), nil
}

// TestCollectDiskIO_NegativeDeltaClamped guards the readMB/writeMB < 0 clamp:
// a counter that goes backwards between the two samples (rollover or a
// garbled read) must report a zero delta, never a negative one.
func TestCollectDiskIO_NegativeDeltaClamped(t *testing.T) {
	prev := SetSource(&decreasingDiskstatsSource{Source: source.NewReplay(source.NewBundle())})
	defer SetSource(prev)

	drives := []models.PhysicalDrive{{Name: "sda"}}
	stats := collectDiskIO(drives)
	if len(stats) != 1 {
		t.Fatalf("expected 1 entry, got %d: %+v", len(stats), stats)
	}
	if stats[0].ReadMBs != 0 || stats[0].WriteMBs != 0 {
		t.Errorf("negative delta must clamp to 0, got read=%v write=%v", stats[0].ReadMBs, stats[0].WriteMBs)
	}
}
