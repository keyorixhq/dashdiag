//go:build linux

package collectors

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// Fixtures include the column-header row that `multipathd show paths format
// "%d %t %s %m"` actually prints first — omitting it (as the original fixtures did)
// hid a bug where the header was parsed as a phantom failed path.
const multipathShowOK = `dev dm_st  vend/prod/rev     multipath
sdb active LUN01 dm-0
sdc active LUN01 dm-0
sdd active LUN02 dm-1
sde active LUN02 dm-1
`

const multipathShowDegraded = `dev dm_st  vend/prod/rev     multipath
sdb active LUN01 dm-0
sdc failed LUN01 dm-0
sdd active LUN02 dm-1
sde active LUN02 dm-1
`

const multipathShowAllFailed = `dev dm_st  vend/prod/rev     multipath
sdb failed LUN01 dm-0
sdc failed LUN01 dm-0
`

// multipathShowRealHeader is verbatim `multipathd show paths format "%d %t %s %m"`
// output from a live 2-path iSCSI multipath device (LIO target). The header row
// previously became a phantom "multipath" device in state "degraded" → a false CRIT.
const multipathShowRealHeader = `dev dm_st  vend/prod/rev     multipath
sdb active LIO-ORG,disk0,4.0 mpatha
sdc active LIO-ORG,disk0,4.0 mpatha
`

// multipathShowOrphan is VERBATIM `multipathd show paths format "%d %t %s %m"`
// from a real host (MacBookAir4,2, Ubuntu) with multipath-tools installed but NO
// multipath maps. sda is an [orphan] (not multipathed), and its vend/prod/rev
// "ATA,APPLE SSD SM128C" contains SPACES. The old fields[3] map parse read "SSD"
// and the orphan became a phantom "all paths failed" device → false CRIT.
const multipathShowOrphan = `dev dm_st vend/prod/rev        multipath
sda undef ATA,APPLE SSD SM128C [orphan]
`

// multipathShowSpacedVendor is a real multipath device whose vend/prod/rev has a
// SPACE ("ATA,Samsung SSD 870"). The map name must still be read from the last
// field, not fields[3].
const multipathShowSpacedVendor = `dev dm_st vend/prod/rev multipath
sdb active ATA,Samsung SSD 870 mpatha
sdc active ATA,Samsung SSD 870 mpatha
`

func findDevice(devices []models.MultipathDevice, dm string) *models.MultipathDevice {
	for i := range devices {
		if devices[i].DM == dm {
			return &devices[i]
		}
	}
	return nil
}

func TestParseMultipathShow(t *testing.T) {
	t.Run("all paths active", func(t *testing.T) {
		devices := parseMultipathShow(multipathShowOK)
		if len(devices) != 2 {
			t.Fatalf("devices = %d, want 2", len(devices))
		}
		for _, d := range devices {
			if d.FailedPaths != 0 {
				t.Errorf("device %s has %d failed paths, want 0", d.Name, d.FailedPaths)
			}
			if d.State != "active" {
				t.Errorf("device %s state = %q, want active", d.Name, d.State)
			}
		}
	})

	t.Run("one path failed = degraded", func(t *testing.T) {
		devices := parseMultipathShow(multipathShowDegraded)
		dm0 := findDevice(devices, "dm-0")
		if dm0 == nil {
			t.Fatal("dm-0 not found")
		}
		if dm0.FailedPaths != 1 {
			t.Errorf("dm-0 failed paths = %d, want 1", dm0.FailedPaths)
		}
		if dm0.ActivePaths != 1 {
			t.Errorf("dm-0 active paths = %d, want 1", dm0.ActivePaths)
		}
		if dm0.State != "degraded" {
			t.Errorf("dm-0 state = %q, want degraded", dm0.State)
		}
	})

	t.Run("orphan path is not a multipath device", func(t *testing.T) {
		// Real MacBookAir4,2 output: multipath-tools installed, no SAN. The [orphan]
		// sda must yield ZERO devices, not a phantom "all paths failed" CRIT.
		devices := parseMultipathShow(multipathShowOrphan)
		if len(devices) != 0 {
			t.Fatalf("orphan path produced %d device(s), want 0: %+v", len(devices), devices)
		}
	})

	t.Run("spaced vendor still maps to last field", func(t *testing.T) {
		devices := parseMultipathShow(multipathShowSpacedVendor)
		if len(devices) != 1 {
			t.Fatalf("devices = %d, want 1", len(devices))
		}
		if devices[0].DM != "mpatha" {
			t.Errorf("map = %q, want mpatha (vend/prod/rev spaces must not shift it)", devices[0].DM)
		}
		if devices[0].ActivePaths != 2 || devices[0].FailedPaths != 0 {
			t.Errorf("paths active/failed = %d/%d, want 2/0", devices[0].ActivePaths, devices[0].FailedPaths)
		}
	})

	t.Run("all paths failed", func(t *testing.T) {
		devices := parseMultipathShow(multipathShowAllFailed)
		if len(devices) != 1 {
			t.Fatalf("devices = %d, want 1", len(devices))
		}
		if devices[0].ActivePaths != 0 {
			t.Errorf("active paths = %d, want 0", devices[0].ActivePaths)
		}
		if devices[0].State != "degraded" {
			t.Errorf("state = %q, want degraded", devices[0].State)
		}
	})

	// A line starting with "hcil" is a column-header from the alternate
	// "%h %d %t %s %m" format — must be skipped, not parsed as a path.
	t.Run("hcil-prefix header line is skipped", func(t *testing.T) {
		out := "hcil dev dm_st vend/prod/rev multipath\nsdb active LIO dm-0\n"
		devices := parseMultipathShow(out)
		if len(devices) != 1 || devices[0].DM != "dm-0" {
			t.Errorf("expected 1 device dm-0, got %+v", devices)
		}
	})

	// A non-empty line with fewer than 4 whitespace-delimited fields cannot be
	// a valid path row — must be skipped without panic.
	t.Run("line with fewer than 4 fields is skipped", func(t *testing.T) {
		out := "a b c\nsdb active LIO dm-0\n"
		devices := parseMultipathShow(out)
		if len(devices) != 1 || devices[0].DM != "dm-0" {
			t.Errorf("expected 1 device dm-0 (short line skipped), got %+v", devices)
		}
	})

	// Regression (found via live 2-path iSCSI multipath on a VM): the format header
	// row must not become a phantom "multipath" device that reads as degraded and
	// raises a false CRIT. The real output has exactly ONE healthy device, mpatha.
	t.Run("format header row is not a phantom device", func(t *testing.T) {
		devices := parseMultipathShow(multipathShowRealHeader)
		if len(devices) != 1 {
			t.Fatalf("devices = %d, want 1 (header must be skipped); got %+v", len(devices), devices)
		}
		d := devices[0]
		if d.DM != "mpatha" {
			t.Errorf("device DM = %q, want mpatha", d.DM)
		}
		if d.ActivePaths != 2 || d.FailedPaths != 0 || d.State != "active" {
			t.Errorf("mpatha = {active:%d failed:%d state:%q}, want {2 0 active}", d.ActivePaths, d.FailedPaths, d.State)
		}
	})
}

// Keep strings import used in other tests in this package
var _ = strings.Contains

// ── parseMultipathL (human-readable `multipath -l` fallback) ────────────────

// multipathLOK is representative `multipath -l` output: one healthy device,
// two active paths.
const multipathLOK = `mpatha (36001405abcdef) dm-0 LIO-ORG,disk0
size=10G features='0' hwhandler='0' wp=rw
` + "`-+- policy='service-time 0' prio=1 status=active" + `
  |- 3:0:0:0 sdb 8:16 active ready running
  ` + "`- 4:0:0:0 sdc 8:32 active ready running"

// multipathLDegraded has one failed path.
const multipathLDegraded = `mpatha (36001405abcdef) dm-0 LIO-ORG,disk0
size=10G features='0' hwhandler='0' wp=rw
` + "`-+- policy='service-time 0' prio=1 status=active" + `
  |- 3:0:0:0 sdb 8:16 active ready running
  ` + "`- 4:0:0:0 sdc 8:32 failed faulty running"

func TestParseMultipathL(t *testing.T) {
	t.Run("all paths active", func(t *testing.T) {
		devices := parseMultipathL(multipathLOK)
		if len(devices) != 1 {
			t.Fatalf("devices = %d, want 1: %+v", len(devices), devices)
		}
		d := devices[0]
		if d.Name != "mpatha" || d.DM != "dm-0" {
			t.Errorf("device = %+v, want Name=mpatha DM=dm-0", d)
		}
		if d.ActivePaths != 2 || d.FailedPaths != 0 || d.State != "active" {
			t.Errorf("active/failed/state = %d/%d/%q, want 2/0/active", d.ActivePaths, d.FailedPaths, d.State)
		}
	})

	t.Run("one path failed = degraded", func(t *testing.T) {
		devices := parseMultipathL(multipathLDegraded)
		if len(devices) != 1 {
			t.Fatalf("devices = %d, want 1: %+v", len(devices), devices)
		}
		d := devices[0]
		if d.ActivePaths != 1 || d.FailedPaths != 1 || d.State != "degraded" {
			t.Errorf("active/failed/state = %d/%d/%q, want 1/1/degraded", d.ActivePaths, d.FailedPaths, d.State)
		}
	})

	t.Run("empty output yields no devices", func(t *testing.T) {
		devices := parseMultipathL("")
		if len(devices) != 0 {
			t.Errorf("expected no devices for empty input, got %+v", devices)
		}
	})

	// When a second device header appears while current != nil, the existing
	// device must be appended before switching to the new one.
	t.Run("two device headers yields two devices", func(t *testing.T) {
		const out = `mpatha (uuid1) dm-0 LIO-ORG,disk0
  |- 3:0:0:0 sdb 8:16 active ready running
mpathb (uuid2) dm-1 LIO-ORG,disk1
  ` + "`- 4:0:0:0 sdc 8:32 active ready running"
		devices := parseMultipathL(out)
		if len(devices) != 2 {
			t.Fatalf("expected 2 devices, got %d: %+v", len(devices), devices)
		}
	})

	// A path line appearing before any device header must be silently skipped
	// (current == nil guard).
	t.Run("path line before first header is skipped", func(t *testing.T) {
		const out = "  |- 3:0:0:0 sdb 8:16 active ready running\n" +
			"mpatha (uuid) dm-0 LIO-ORG,disk0\n"
		devices := parseMultipathL(out)
		if len(devices) != 0 {
			t.Errorf("expected no complete devices (sdb path appeared before header), got %+v", devices)
		}
	})

	t.Run("nvme path line recognized", func(t *testing.T) {
		const out = `mpathb (uuid) dm-1 NVME,disk
size=1T features='0' hwhandler='0' wp=rw
` + "`-+- policy='queue-length 0' prio=50 status=active" + `
  ` + "`- 0:0:0:0 nvme0n1 259:0 active ready running"
		devices := parseMultipathL(out)
		if len(devices) != 1 || devices[0].ActivePaths != 1 {
			t.Fatalf("expected 1 device with 1 active nvme path, got %+v", devices)
		}
	})
}

// ── Collect() / identity / gate tests ────────────────────────────────────────

func TestMultipathCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewMultipathCollector()
	if c.Name() != "Multipath" {
		t.Errorf("Name() = %q, want Multipath", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

func TestIsMultipathPresent(t *testing.T) {
	t.Run("binary absent (no lookpath recording)", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if IsMultipathPresent() {
			t.Error("expected false when multipathd binary is absent")
		}
	})
}

// TestIsMultipathPresent_LookpathAndProcess drives the full gate: lookPath
// success (via Cached "lookpath/multipathd") AND anyProcessNamed.
func TestIsMultipathPresent_LookpathAndProcess(t *testing.T) {
	t.Run("present via running daemon", func(t *testing.T) {
		withCombinedFixture(t,
			map[string][]byte{"lookpath/multipathd": []byte("/sbin/multipathd")},
			nil,
			func(b *source.Bundle) {
				b.PutDir("/proc", []string{"100"})
				b.PutFile("/proc/100/comm", []byte("multipathd\n"))
			})
		if !IsMultipathPresent() {
			t.Error("expected true when multipathd is on PATH and the daemon process is running")
		}
	})

	t.Run("present via sysfs maps when daemon not running", func(t *testing.T) {
		withCombinedFixture(t,
			map[string][]byte{"lookpath/multipathd": []byte("/sbin/multipathd")},
			nil,
			func(b *source.Bundle) {
				b.PutDir("/proc", []string{})
				b.PutDir("/sys/block", []string{"sda", "dm-0"})
				b.PutFile("/sys/block/dm-0/dm/uuid", []byte("mpath-36001405abcdef\n"))
			})
		if !IsMultipathPresent() {
			t.Error("expected true via sysfs dm-uuid map when daemon isn't running")
		}
	})

	t.Run("absent: on PATH but no daemon and no maps", func(t *testing.T) {
		withCombinedFixture(t,
			map[string][]byte{"lookpath/multipathd": []byte("/sbin/multipathd")},
			nil,
			func(b *source.Bundle) {
				b.PutDir("/proc", []string{})
				b.PutDir("/sys/block", []string{"sda"})
			})
		if IsMultipathPresent() {
			t.Error("expected false: multipath-tools installed but never used (no daemon, no maps)")
		}
	})

	t.Run("binary not on PATH short-circuits", func(t *testing.T) {
		withCombinedFixture(t, nil, nil, func(_ *source.Bundle) {})
		if IsMultipathPresent() {
			t.Error("expected false when lookPath finds nothing (Cached recording gap)")
		}
	})
}

// TestMultipathMapsPresentFixture adds fixture-source coverage of
// multipathMapsPresent alongside the real-tempdir TestMultipathMapsPresent in
// multipath_maps_linux_test.go — in particular the unreadable-dir and
// unreadable-uuid-file degrade paths that test doesn't exercise.
func TestMultipathMapsPresentFixture(t *testing.T) {
	t.Run("finds a mpath- uuid device", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/sys/block", []string{"sda", "dm-0", "dm-1"})
			b.PutFile("/sys/block/dm-0/dm/uuid", []byte("LVM-abcdef\n"))
			b.PutFile("/sys/block/dm-1/dm/uuid", []byte("mpath-36001405abcdef\n"))
		})
		if !multipathMapsPresent("/sys/block") {
			t.Error("expected true: dm-1 has a mpath- uuid prefix")
		}
	})

	t.Run("no dm- devices at all", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/sys/block", []string{"sda", "nvme0n1"})
		})
		if multipathMapsPresent("/sys/block") {
			t.Error("expected false: no dm- prefixed entries")
		}
	})

	t.Run("dm- device present but not multipath (LVM)", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/sys/block", []string{"dm-0"})
			b.PutFile("/sys/block/dm-0/dm/uuid", []byte("LVM-abcdef\n"))
		})
		if multipathMapsPresent("/sys/block") {
			t.Error("expected false: dm-0 uuid does not have mpath- prefix")
		}
	})

	t.Run("unreadable dir returns false", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if multipathMapsPresent("/sys/block") {
			t.Error("expected false when /sys/block can't be read")
		}
	})

	t.Run("dm uuid file unreadable is skipped, not fatal", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/sys/block", []string{"dm-0"})
			// dm-0/dm/uuid deliberately not seeded — readFile fails, skip.
		})
		if multipathMapsPresent("/sys/block") {
			t.Error("expected false when the uuid file can't be read")
		}
	})
}

// TestMultipathCollector_Collect_NotPresent guards the gate-off path: no
// lookpath/multipathd recording means IsMultipathPresent() is false.
func TestMultipathCollector_Collect_NotPresent(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {})
	c := NewMultipathCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.MultipathInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.MultipathInfo", raw)
	}
	if info.Available {
		t.Errorf("expected Available=false when multipath is not present, got %+v", info)
	}
}

// TestMultipathCollector_Collect_ShowPathsSucceeds exercises the primary
// "multipathd show paths" path, with the format-header row present in the
// fixture (real tool output includes it — see the parseMultipathShow doc).
func TestMultipathCollector_Collect_ShowPathsSucceeds(t *testing.T) {
	withCombinedFixture(t,
		map[string][]byte{"lookpath/multipathd": []byte("/sbin/multipathd")},
		nil,
		func(b *source.Bundle) {
			b.PutDir("/proc", []string{"100"})
			b.PutFile("/proc/100/comm", []byte("multipathd\n"))
			b.PutCmd("multipathd", []string{"show", "paths", "format", "%d %t %s %m"}, multipathShowOK, 0)
		})
	c := NewMultipathCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MultipathInfo)
	if !info.Available {
		t.Error("expected Available=true")
	}
	if len(info.Devices) != 2 {
		t.Fatalf("Devices = %+v, want 2", info.Devices)
	}
}

// TestMultipathCollector_Collect_ShowPathsFailsFallsBackToDashL guards the
// fallback: `multipathd show paths` errors, `multipath -l` succeeds instead.
func TestMultipathCollector_Collect_ShowPathsFailsFallsBackToDashL(t *testing.T) {
	withCombinedFixture(t,
		map[string][]byte{"lookpath/multipathd": []byte("/sbin/multipathd")},
		nil,
		func(b *source.Bundle) {
			b.PutDir("/proc", []string{"100"})
			b.PutFile("/proc/100/comm", []byte("multipathd\n"))
			b.PutCmd("multipathd", []string{"show", "paths", "format", "%d %t %s %m"}, "", 1)
			b.PutCmd("multipath", []string{"-l"}, multipathLOK, 0)
		})
	c := NewMultipathCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MultipathInfo)
	if !info.Available {
		t.Error("expected Available=true")
	}
	if len(info.Devices) != 1 || info.Devices[0].Name != "mpatha" {
		t.Fatalf("Devices = %+v, want 1 device named mpatha (parsed via multipath -l fallback)", info.Devices)
	}
}

// TestMultipathCollector_Collect_BothCommandsFail guards the actionable-error
// row: both multipathd and multipath fail — Available stays true (daemon is
// running) with a Status/StatusReason describing the read failure.
func TestMultipathCollector_Collect_BothCommandsFail(t *testing.T) {
	withCombinedFixture(t,
		map[string][]byte{"lookpath/multipathd": []byte("/sbin/multipathd")},
		nil,
		func(b *source.Bundle) {
			b.PutDir("/proc", []string{"100"})
			b.PutFile("/proc/100/comm", []byte("multipathd\n"))
			b.PutCmd("multipathd", []string{"show", "paths", "format", "%d %t %s %m"}, "", 1)
			b.PutCmd("multipath", []string{"-l"}, "", 1)
		})
	c := NewMultipathCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MultipathInfo)
	if !info.Available {
		t.Error("expected Available=true (daemon running, just unreadable)")
	}
	if info.Status != "error" {
		t.Errorf("Status = %q, want error", info.Status)
	}
	if info.StatusReason == "" {
		t.Error("expected a non-empty StatusReason describing the read failure")
	}
}

// TestMultipathCollector_Collect_NoDevicesGatesOff guards the "installed but
// zero maps configured" case: multipathd runs, but the parsed device list is
// empty (only the header row was ever printed) — Collect must return
// (nil, nil), matching the "no SAN" absent-section contract.
func TestMultipathCollector_Collect_NoDevicesGatesOff(t *testing.T) {
	withCombinedFixture(t,
		map[string][]byte{"lookpath/multipathd": []byte("/sbin/multipathd")},
		nil,
		func(b *source.Bundle) {
			b.PutDir("/proc", []string{"100"})
			b.PutFile("/proc/100/comm", []byte("multipathd\n"))
			b.PutCmd("multipathd", []string{"show", "paths", "format", "%d %t %s %m"},
				"dev dm_st  vend/prod/rev     multipath\n", 0)
		})
	c := NewMultipathCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("expected nil info when no devices parsed, got %+v", raw)
	}
}
