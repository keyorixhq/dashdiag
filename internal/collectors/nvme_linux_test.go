//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestNVMeCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewNVMeCollector()
	if c.Name() != "Drives" {
		t.Errorf("Name() = %q, want Drives", c.Name())
	}
	if c.Timeout() != 8*time.Second {
		t.Errorf("Timeout() = %v, want 8s", c.Timeout())
	}
}

// TestNvmeUnreadReason_ToolAbsent guards the deterministic (euid-independent)
// branch: nvme-cli genuinely absent classifies as "tool_absent" regardless of
// privilege. The root/non-root split inside nvmeUnreadReason depends on the
// real os.Geteuid() syscall (not source-routed) — see the report for why that
// branch isn't separately unit-tested here.
func TestNvmeUnreadReason_ToolAbsent(t *testing.T) {
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		// No lookpath/nvme Cached entry and no sbin Stat entries seeded ->
		// sbinToolPath("nvme") == "".
	})
	if got := nvmeUnreadReason(); got != "tool_absent" {
		t.Errorf("nvmeUnreadReason() = %q, want tool_absent", got)
	}
}

func TestReadFileStr(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/sys/class/nvme/nvme0/model", []byte("Samsung SSD 980\n"))
		})
		if got := readFileStr("/sys/class/nvme/nvme0/model"); got != "Samsung SSD 980\n" {
			t.Errorf("readFileStr() = %q, want %q", got, "Samsung SSD 980\n")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		if got := readFileStr("/sys/class/nvme/nvme0/model"); got != "" {
			t.Errorf("readFileStr() = %q, want empty", got)
		}
	})
}

// TestNVMeMountPoints guards the partition-matching logic against a
// controller's mount points: a matching partition on a Linux fs, a matching
// partition excluded because it's swap/none, a non-matching device, and an
// empty /proc/mounts.
func TestNVMeMountPoints(t *testing.T) {
	t.Run("matching partition mounted on Linux fs", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/mounts", []byte("/dev/nvme0n1p1 / ext4 rw,relatime 0 0\n"))
		})
		mounts, hasLinux := nvmeMountPoints("/sys/class/nvme/nvme0")
		if len(mounts) != 1 || mounts[0] != "/" || !hasLinux {
			t.Errorf("got mounts=%v hasLinux=%v, want [/] true", mounts, hasLinux)
		}
	})

	t.Run("swap/none mountpoint excluded", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/mounts", []byte(
				"/dev/nvme0n1p2 none swap sw 0 0\n"+
					"/dev/nvme0n1p3 swap swap sw 0 0\n"))
		})
		mounts, hasLinux := nvmeMountPoints("/sys/class/nvme/nvme0")
		if len(mounts) != 0 || hasLinux {
			t.Errorf("got mounts=%v hasLinux=%v, want none/false", mounts, hasLinux)
		}
	})

	t.Run("non-matching device excluded", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/mounts", []byte("/dev/sda1 /boot ext4 rw,relatime 0 0\n"))
		})
		mounts, hasLinux := nvmeMountPoints("/sys/class/nvme/nvme0")
		if len(mounts) != 0 || hasLinux {
			t.Errorf("got mounts=%v hasLinux=%v, want none/false", mounts, hasLinux)
		}
	})

	t.Run("empty /proc/mounts", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		mounts, hasLinux := nvmeMountPoints("/sys/class/nvme/nvme0")
		if mounts != nil || hasLinux {
			t.Errorf("got mounts=%v hasLinux=%v, want nil/false", mounts, hasLinux)
		}
	})
}

// TestNVMeCollector_Collect_ModelSanitizesControlChars is the regression test
// for internal-collectors-24-02: dev.Model bypasses Insight.Message entirely
// (only dev.Name flows there), so collector-layer sanitization is the only
// thing protecting a crafted sysfs model string from control/ANSI bytes.
func TestNVMeCollector_Collect_ModelSanitizesControlChars(t *testing.T) {
	esc := string(rune(27))
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/nvme/nvme*", []string{"/sys/class/nvme/nvme0"})
		b.PutFile("/sys/class/nvme/nvme0/model", []byte("Evil"+esc+"[31mDrive\n"))
		b.PutFile("/sys/class/nvme/nvme0/state", []byte("live\n"))
		b.PutCmd("nvme", []string{"smart-log", "/dev/nvme0", "--output-format=normal"}, "", 1)
		b.PutCmdNotFound("smartctl", []string{"--scan-open", "--json=c"})
	})
	c := NewNVMeCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.NVMeInfo)
	if len(info.Devices) != 1 {
		t.Fatalf("Devices = %+v, want exactly 1", info.Devices)
	}
	if info.Devices[0].Model != "Evil[31mDrive" {
		t.Errorf("Model = %q, want ESC stripped to Evil[31mDrive", info.Devices[0].Model)
	}
}

// TestCollectSATADrives_OpenErrorSanitizesControlChars is the regression test
// for internal-collectors-24-02: dev.Error ("smartctl: " + open_error)
// bypasses Insight.Message entirely, so the open_error component must be
// sanitized before concatenation.
func TestCollectSATADrives_OpenErrorSanitizesControlChars(t *testing.T) {
	esc := string(rune(27))
	type scanDevice struct {
		Name      string `json:"name"`
		Protocol  string `json:"protocol"`
		OpenError string `json:"open_error"`
	}
	payload := struct {
		Devices []scanDevice `json:"devices"`
	}{
		Devices: []scanDevice{{Name: "/dev/sda", Protocol: "ATA", OpenError: "No such device" + esc + "[0m"}},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--scan-open", "--json=c"}, string(raw), 0)
	})
	info := &models.NVMeInfo{}
	collectSATADrives(context.Background(), info)
	if len(info.SATADevices) != 1 {
		t.Fatalf("SATADevices = %+v, want exactly 1", info.SATADevices)
	}
	if info.SATADevices[0].Error != "smartctl: No such device[0m" {
		t.Errorf("Error = %q, want ESC stripped", info.SATADevices[0].Error)
	}
}

// TestApplySATASmartJSON_ModelSanitizesControlChars is the regression test
// for internal-collectors-24-02: applySATASmartJSON's dev.Model bypasses
// Insight.Message entirely, so it must be sanitized at assignment.
func TestApplySATASmartJSON_ModelSanitizesControlChars(t *testing.T) {
	t.Parallel()
	esc := string(rune(27))
	payload := struct {
		ModelName string `json:"model_name"`
	}{ModelName: "Evil" + esc + "[31mDrive"}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var d models.SATADevice
	applySATASmartJSON(string(raw), &d)
	if d.Model != "Evil[31mDrive" {
		t.Errorf("Model = %q, want ESC stripped to Evil[31mDrive", d.Model)
	}
}

// TestNVMeCollect_SkipsNamespaceEntry covers nvme_linux.go:60.30,61.12 — the
// !isNVMeController(base) continue branch, triggered when the nvme* glob
// returns a namespace (nvme0n1) rather than a controller (nvme0). The namespace
// must be silently skipped and Collect must return (nil, nil) — same as no
// devices — since no valid controller was found.
func TestNVMeCollect_SkipsNamespaceEntry(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// nvme0n1 is a namespace, not a controller — isNVMeController returns false.
		b.PutGlob("/sys/class/nvme/nvme*", []string{"/sys/class/nvme/nvme0n1"})
		b.PutCmdNotFound("smartctl", []string{"--scan-open", "--json=c"})
	})
	c := NewNVMeCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("Collect() = %v, want nil (namespace must be skipped, no devices)", raw)
	}
}

// TestNVMeCollector_Collect_NoDevices guards the explicit gate-off case: no
// NVMe controllers and no SATA/SAS devices -> Collect returns (nil, nil).
func TestNVMeCollector_Collect_NoDevices(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/nvme/nvme*", nil)
		b.PutCmdNotFound("smartctl", []string{"--scan-open", "--json=c"})
	})
	c := NewNVMeCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("Collect() = %v, want nil (no drives at all)", raw)
	}
}

// TestNVMeCollector_Collect_SmartLogSuccess exercises one NVMe controller with
// a successful, parseable smart-log.
func TestNVMeCollector_Collect_SmartLogSuccess(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/nvme/nvme*", []string{"/sys/class/nvme/nvme0"})
		b.PutFile("/sys/class/nvme/nvme0/model", []byte("Samsung SSD 980\n"))
		b.PutFile("/sys/class/nvme/nvme0/state", []byte("live\n"))
		b.PutCmd("nvme", []string{"smart-log", "/dev/nvme0", "--output-format=normal"},
			"critical_warning			: 0\npercentage_used			: 7%\nmedia_errors			: 0\n", 0)
		b.PutFile("/proc/mounts", []byte("/dev/nvme0n1p1 / ext4 rw,relatime 0 0\n"))
		b.PutCmdNotFound("smartctl", []string{"--scan-open", "--json=c"})
	})
	c := NewNVMeCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.NVMeInfo)
	if len(info.Devices) != 1 {
		t.Fatalf("Devices = %+v, want exactly 1", info.Devices)
	}
	dev := info.Devices[0]
	if !dev.SmartRead || dev.SmartUnreadReason != "" {
		t.Errorf("dev = %+v, want SmartRead=true, no unread reason", dev)
	}
	if dev.SmartDangerousFieldsUnread {
		t.Error("SmartDangerousFieldsUnread = true, want false — all three dangerous fields were present")
	}
	if dev.Model != "Samsung SSD 980" || dev.PercentageUsed != 7 {
		t.Errorf("dev = %+v, want Model=Samsung SSD 980 PercentageUsed=7", dev)
	}
	if len(dev.MountPoints) != 1 || dev.MountPoints[0] != "/" || !dev.HasLinux {
		t.Errorf("dev mount info = %+v, want [/] hasLinux=true", dev)
	}
}

// TestNVMeCollector_Collect_SmartLogCommandFails guards the branch where the
// nvme smart-log command itself errors — SmartUnreadReason must be set via
// nvmeUnreadReason(). With no lookpath/nvme fixture seeded, sbinToolPath("nvme")
// is "" (tool genuinely absent from this test's perspective), so the reason is
// deterministically "tool_absent" regardless of euid.
func TestNVMeCollector_Collect_SmartLogCommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/nvme/nvme*", []string{"/sys/class/nvme/nvme0"})
		b.PutFile("/sys/class/nvme/nvme0/model", []byte("Samsung SSD 980\n"))
		b.PutFile("/sys/class/nvme/nvme0/state", []byte("live\n"))
		b.PutCmd("nvme", []string{"smart-log", "/dev/nvme0", "--output-format=normal"}, "", 1)
		b.PutCmdNotFound("smartctl", []string{"--scan-open", "--json=c"})
	})
	c := NewNVMeCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.NVMeInfo)
	if len(info.Devices) != 1 {
		t.Fatalf("Devices = %+v, want exactly 1", info.Devices)
	}
	dev := info.Devices[0]
	if dev.SmartRead {
		t.Error("SmartRead should be false when smart-log command fails")
	}
	if dev.SmartUnreadReason != "tool_absent" {
		t.Errorf("SmartUnreadReason = %q, want tool_absent", dev.SmartUnreadReason)
	}
}

// TestNVMeCollector_Collect_SmartLogUnparseable guards the documented
// bug-fix pattern: smart-log exits 0 but its output has no recognized fields
// (banner-only text) -> SmartRead=false, SmartUnreadReason="error" (NOT the
// nvmeUnreadReason() classification, since the command itself succeeded).
func TestNVMeCollector_Collect_SmartLogUnparseable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/nvme/nvme*", []string{"/sys/class/nvme/nvme0"})
		b.PutFile("/sys/class/nvme/nvme0/model", []byte("Samsung SSD 980\n"))
		b.PutFile("/sys/class/nvme/nvme0/state", []byte("live\n"))
		b.PutCmd("nvme", []string{"smart-log", "/dev/nvme0", "--output-format=normal"},
			"WARNING: nvme-cli deprecation notice\nnonsense line\n", 0)
		b.PutCmdNotFound("smartctl", []string{"--scan-open", "--json=c"})
	})
	c := NewNVMeCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.NVMeInfo)
	if len(info.Devices) != 1 {
		t.Fatalf("Devices = %+v, want exactly 1", info.Devices)
	}
	dev := info.Devices[0]
	if dev.SmartRead {
		t.Error("SmartRead should be false for unparseable output")
	}
	if dev.SmartUnreadReason != "error" {
		t.Errorf("SmartUnreadReason = %q, want error", dev.SmartUnreadReason)
	}
}

// ── collectSATADrives ────────────────────────────────────────────────────────

func TestCollectSATADrives_ScanFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("smartctl", []string{"--scan-open", "--json=c"})
	})
	info := &models.NVMeInfo{}
	collectSATADrives(context.Background(), info)
	if info.SATADevices != nil {
		t.Errorf("SATADevices = %+v, want nil when smartctl scan fails", info.SATADevices)
	}
}

// TestCollectSATADrives_SkipsNVMeProtocol guards that a scanned device whose
// protocol contains "nvme" is skipped (handled by the NVMe path above, not
// duplicated here).
func TestCollectSATADrives_SkipsNVMeProtocol(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--scan-open", "--json=c"},
			`{"devices":[{"name":"/dev/nvme0","protocol":"NVMe"}]}`, 0)
	})
	info := &models.NVMeInfo{}
	collectSATADrives(context.Background(), info)
	if len(info.SATADevices) != 0 {
		t.Errorf("SATADevices = %+v, want empty (NVMe protocol device must be skipped)", info.SATADevices)
	}
}

func TestCollectSATADrives_OpenErrorPermissionDenied(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--scan-open", "--json=c"},
			`{"devices":[{"name":"/dev/sda","protocol":"ATA","open_error":"Permission denied"}]}`, 0)
	})
	info := &models.NVMeInfo{}
	collectSATADrives(context.Background(), info)
	if len(info.SATADevices) != 1 {
		t.Fatalf("SATADevices = %+v, want exactly 1", info.SATADevices)
	}
	dev := info.SATADevices[0]
	if dev.SmartUnreadReason != "needs_root" {
		t.Errorf("SmartUnreadReason = %q, want needs_root", dev.SmartUnreadReason)
	}
	if dev.Type != "sata" {
		t.Errorf("Type = %q, want sata", dev.Type)
	}
}

func TestCollectSATADrives_OpenErrorOther(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--scan-open", "--json=c"},
			`{"devices":[{"name":"/dev/sda","protocol":"ATA","open_error":"No such device"}]}`, 0)
	})
	info := &models.NVMeInfo{}
	collectSATADrives(context.Background(), info)
	if len(info.SATADevices) != 1 {
		t.Fatalf("SATADevices = %+v, want exactly 1", info.SATADevices)
	}
	if info.SATADevices[0].SmartUnreadReason != "error" {
		t.Errorf("SmartUnreadReason = %q, want error", info.SATADevices[0].SmartUnreadReason)
	}
}

// TestCollectSATADrives_SuccessfulRead exercises the follow-up smartctl -a
// call succeeding — applySATASmartJSON populates the device.
func TestCollectSATADrives_SuccessfulRead(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--scan-open", "--json=c"},
			`{"devices":[{"name":"/dev/sda","protocol":"ATA"}]}`, 0)
		b.PutCmd("smartctl", []string{"--json=c", "-a", "/dev/sda"},
			`{"model_name":"X","smart_status":{"passed":true},"temperature":{"current":34}}`, 0)
	})
	info := &models.NVMeInfo{}
	collectSATADrives(context.Background(), info)
	if len(info.SATADevices) != 1 {
		t.Fatalf("SATADevices = %+v, want exactly 1", info.SATADevices)
	}
	dev := info.SATADevices[0]
	if !dev.SmartRead || !dev.SmartOK || dev.TempC != 34 {
		t.Errorf("dev = %+v, want SmartRead=true SmartOK=true temp=34", dev)
	}
}

// TestCollectSATADrives_FollowUpCommandFails guards the final failure branch:
// the follow-up smartctl -a call itself fails (non-zero exit, empty output).
func TestCollectSATADrives_FollowUpCommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--scan-open", "--json=c"},
			`{"devices":[{"name":"/dev/sda","protocol":"ATA"}]}`, 0)
		b.PutCmd("smartctl", []string{"--json=c", "-a", "/dev/sda"}, "", 1)
	})
	info := &models.NVMeInfo{}
	collectSATADrives(context.Background(), info)
	if len(info.SATADevices) != 1 {
		t.Fatalf("SATADevices = %+v, want exactly 1", info.SATADevices)
	}
	dev := info.SATADevices[0]
	if dev.Error != "smartctl failed" {
		t.Errorf("Error = %q, want %q", dev.Error, "smartctl failed")
	}
	if dev.SmartUnreadReason != "error" {
		t.Errorf("SmartUnreadReason = %q, want error", dev.SmartUnreadReason)
	}
}

// parseNVMeSmartLog must read `critical_warning` correctly. `nvme smart-log
// --output-format=normal` prints it as %#x (nvme-cli 2.13), so a non-zero
// warning is hex ("0x4"); the old strconv.Atoi path returned 0 for that, hiding
// a failing drive behind heuristics.go's `CriticalWarning > 0` — a false-OK.
func TestParseNVMeCriticalWarningHex(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want int
	}{
		{"zero (plain)", "critical_warning : 0\n", 0},
		{"hex spare-below-threshold bit", "critical_warning : 0x1\n", 1},
		{"hex reliability-degraded bit", "critical_warning : 0x4\n", 4},
		{"hex multiple bits", "critical_warning : 0x1d\n", 0x1d},
		{"decimal still parses", "critical_warning : 4\n", 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var dev models.NVMeDevice
			parseNVMeSmartLog(c.out, &dev)
			if dev.CriticalWarning != c.want {
				t.Errorf("CriticalWarning = %d (0x%x), want %d", dev.CriticalWarning, dev.CriticalWarning, c.want)
			}
		})
	}
}

// applySATASmartJSON must set SmartRead only when smartctl actually reported a
// verdict. `smartctl --json -a` emits JSON with NO smart_status for USB bridges,
// RAID members, and virtual disks — without the SmartRead distinction those
// defaulted SmartOK=false and fired a false "drive may be failing" CRIT.
func TestApplySATASmartJSON(t *testing.T) {
	t.Run("verdict passed", func(t *testing.T) {
		var d models.SATADevice
		applySATASmartJSON(`{"model_name":"X","smart_status":{"passed":true},"temperature":{"current":34}}`, &d)
		if !d.SmartRead || !d.SmartOK || d.TempC != 34 {
			t.Fatalf("got SmartRead=%v SmartOK=%v temp=%d, want true,true,34", d.SmartRead, d.SmartOK, d.TempC)
		}
	})
	t.Run("verdict failed", func(t *testing.T) {
		var d models.SATADevice
		applySATASmartJSON(`{"smart_status":{"passed":false}}`, &d)
		if !d.SmartRead || d.SmartOK {
			t.Fatalf("got SmartRead=%v SmartOK=%v, want true,false", d.SmartRead, d.SmartOK)
		}
	})
	t.Run("no smart_status — unread, classified no_smart (virtual disk)", func(t *testing.T) {
		var d models.SATADevice
		// Realistic smartctl output for a drive behind a controller: JSON present,
		// no smart_status object.
		applySATASmartJSON(`{"model_name":"VMware Virtual disk","temperature":{"current":0}}`, &d)
		if d.SmartRead {
			t.Fatalf("SmartRead=true with no smart_status — would fire a false CRIT")
		}
		if d.SmartUnreadReason != "no_smart" {
			t.Fatalf("reason=%q, want no_smart — a SMART-less device must not read as a privilege failure", d.SmartUnreadReason)
		}
	})
	t.Run("permission denied — classified needs_root", func(t *testing.T) {
		var d models.SATADevice
		// `smartctl --json=c` still emits JSON on a non-root open failure, with the
		// error in smartctl.messages and no smart_status.
		applySATASmartJSON(`{"smartctl":{"messages":[{"string":"Smartctl open device: /dev/sda failed: Permission denied"}]}}`, &d)
		if d.SmartRead {
			t.Fatalf("SmartRead=true on a permission error")
		}
		if d.SmartUnreadReason != "needs_root" {
			t.Fatalf("reason=%q, want needs_root", d.SmartUnreadReason)
		}
	})
	t.Run("verdict present — no unread reason", func(t *testing.T) {
		var d models.SATADevice
		applySATASmartJSON(`{"smart_status":{"passed":true}}`, &d)
		if d.SmartUnreadReason != "" {
			t.Fatalf("reason=%q, want empty when SMART was read", d.SmartUnreadReason)
		}
	})
	t.Run("garbled JSON — unread", func(t *testing.T) {
		var d models.SATADevice
		applySATASmartJSON(`not json`, &d)
		if d.SmartRead || d.SmartOK {
			t.Fatalf("garbled input produced a verdict: SmartRead=%v SmartOK=%v", d.SmartRead, d.SmartOK)
		}
	})
}

// Negative or garbled counters must not reach a field that a `> 0` / `>= N`
// health check reads — a negative slips under the threshold and reads healthy.
func TestParseNVMeNegativeCountersRejected(t *testing.T) {
	var dev models.NVMeDevice
	parseNVMeSmartLog(
		"media_errors : -5\n"+
			"percentage_used : -3%\n"+
			"unsafe_shutdowns : -1\n"+
			"critical_warning : -2\n",
		&dev)
	if dev.MediaErrors != 0 || dev.PercentageUsed != 0 || dev.UnsafeShutdowns != 0 || dev.CriticalWarning != 0 {
		t.Errorf("negative values leaked: media=%d pct=%d unsafe=%d crit=%d (want all 0)",
			dev.MediaErrors, dev.PercentageUsed, dev.UnsafeShutdowns, dev.CriticalWarning)
	}

	// Valid values still parse.
	var ok models.NVMeDevice
	parseNVMeSmartLog(
		"media_errors : 7\npercentage_used : 12%\nunsafe_shutdowns : 3\npower_on_hours : 1234\n",
		&ok)
	if ok.MediaErrors != 7 || ok.PercentageUsed != 12 || ok.UnsafeShutdowns != 3 || ok.PowerOnHours != 1234 {
		t.Errorf("valid values mis-parsed: media=%d pct=%d unsafe=%d poh=%d",
			ok.MediaErrors, ok.PercentageUsed, ok.UnsafeShutdowns, ok.PowerOnHours)
	}
}

// TestParseNVMeSmartLogReportsParseSuccess pins the SmartRead signal: real smart-log
// output returns true (and populates fields), while exit-0-but-unparseable output
// returns false so the all-zero health fields aren't read as a healthy drive.
func TestParseNVMeSmartLogReportsParseSuccess(t *testing.T) {
	var d models.NVMeDevice
	if parseNVMeSmartLog("WARNING: nvme-cli deprecation notice\nnonsense line\n", &d) {
		t.Error("unparseable smart-log must return false (no recognized fields)")
	}
	var d2 models.NVMeDevice
	real := "critical_warning			: 0\npercentage_used			: 7%\nmedia_errors			: 0\n"
	if !parseNVMeSmartLog(real, &d2) {
		t.Error("real smart-log with recognized fields must return true")
	}
	if d2.PercentageUsed != 7 {
		t.Errorf("PercentageUsed = %d, want 7", d2.PercentageUsed)
	}
	if d2.SmartDangerousFieldsUnread {
		t.Error("SmartDangerousFieldsUnread = true, want false — all three dangerous fields were present")
	}
}

// TestParseNVMeSmartLog_DangerousFieldMissing is the regression guard for
// internal-collectors-24-01: a smart-log that includes only a benign field
// (power_on_hours) while critical_warning/media_errors/percentage_used are
// absent must still return parsedAny=true (so SmartRead becomes true), but
// SmartDangerousFieldsUnread must flag that the safety-critical fields were
// never actually read — SmartRead alone does not prove the drive is
// verified-healthy.
func TestParseNVMeSmartLog_DangerousFieldMissing(t *testing.T) {
	t.Parallel()
	var d models.NVMeDevice
	out := "power_on_hours			: 500\n" // only a benign field present
	if !parseNVMeSmartLog(out, &d) {
		t.Fatal("expected parsedAny=true — power_on_hours is a recognized field")
	}
	if !d.SmartDangerousFieldsUnread {
		t.Error("SmartDangerousFieldsUnread = false, want true — critical_warning/media_errors/percentage_used were never present")
	}

	// Partial: two of three dangerous fields present, one missing (media_errors).
	var d2 models.NVMeDevice
	partial := "critical_warning			: 0\npercentage_used			: 7%\n"
	if !parseNVMeSmartLog(partial, &d2) {
		t.Fatal("expected parsedAny=true")
	}
	if !d2.SmartDangerousFieldsUnread {
		t.Error("SmartDangerousFieldsUnread = false, want true — media_errors is missing")
	}
}

// TestParseNVMeSmartLog_AllRecognizedKeys guards every switch case in
// parseNVMeSmartLog — available_spare, available_spare_threshold,
// power_cycles, and temperature were previously only exercised indirectly (or
// not at all), leaving those branches uncovered.
func TestParseNVMeSmartLog_AllRecognizedKeys(t *testing.T) {
	t.Parallel()
	var d models.NVMeDevice
	out := "critical_warning			: 0\n" +
		"temperature				: 111 F (317 K)\n" +
		"available_spare			: 100%\n" +
		"available_spare_threshold		: 10%\n" +
		"percentage_used			: 7%\n" +
		"media_errors			: 0\n" +
		"unsafe_shutdowns			: 2\n" +
		"power_on_hours			: 500\n" +
		"power_cycles			: 42\n"
	if !parseNVMeSmartLog(out, &d) {
		t.Fatal("expected parsedAny=true for a full recognized log")
	}
	if d.AvailableSparePct != 100 {
		t.Errorf("AvailableSparePct = %d, want 100", d.AvailableSparePct)
	}
	if d.SpareThresholdPct != 10 {
		t.Errorf("SpareThresholdPct = %d, want 10", d.SpareThresholdPct)
	}
	if d.PowerCycles != 42 {
		t.Errorf("PowerCycles = %d, want 42", d.PowerCycles)
	}
	if d.TempC <= 0 {
		t.Errorf("TempC = %v, want > 0 (parsed from Kelvin)", d.TempC)
	}
}

// TestParseBitmask_EmptyAndGarbled guards the empty-fields short-circuit and
// the non-numeric parse-error path directly (parseNVMeSmartLog only ever feeds
// it non-empty, mostly-valid tokens, so these branches need a direct call).
func TestParseBitmask_EmptyAndGarbled(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"empty string", "", 0},
		{"whitespace only", "   ", 0},
		{"garbled non-numeric", "not-a-number", 0},
		{"negative decimal", "-1", 0},
		{"zero", "0", 0},
		{"hex value", "0x4", 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := parseBitmask(c.in); got != c.want {
				t.Errorf("parseBitmask(%q) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

// TestParseInt_EmptyAndGarbled guards parseInt's empty-fields short-circuit
// and non-numeric parse-error path directly.
func TestParseInt_EmptyAndGarbled(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"empty string", "", 0},
		{"whitespace only", "  ", 0},
		{"garbled non-numeric", "abc", 0},
		{"negative", "-5", 0},
		{"valid with trailing unit text", "60783741 (31.12 TB)", 60783741},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := parseInt(c.in); got != c.want {
				t.Errorf("parseInt(%q) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

// TestCollectSATADrives_BadJSONFromScan covers nvme_linux.go:293 — the early
// return when smartctl --scan-open emits non-JSON output (e.g. a warning message).
func TestCollectSATADrives_BadJSONFromScan(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--scan-open", "--json=c"}, "not valid json", 0)
	})
	info := &models.NVMeInfo{}
	collectSATADrives(context.Background(), info)
	if len(info.SATADevices) != 0 {
		t.Errorf("SATADevices = %+v, want nil when scan JSON is unparseable", info.SATADevices)
	}
}

// TestCollectSATADrives_SASProtocol covers nvme_linux.go:308 — a device whose
// protocol contains "scsi" or "sas" must produce Type="sas".
func TestCollectSATADrives_SASProtocol(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--scan-open", "--json=c"},
			`{"devices":[{"name":"/dev/sda","protocol":"SCSI","open_error":"Permission denied"}]}`, 0)
	})
	info := &models.NVMeInfo{}
	collectSATADrives(context.Background(), info)
	if len(info.SATADevices) != 1 {
		t.Fatalf("SATADevices = %+v, want 1 for SCSI protocol device", info.SATADevices)
	}
	if info.SATADevices[0].Type != "sas" {
		t.Errorf("Type = %q, want sas for SCSI protocol", info.SATADevices[0].Type)
	}
}

// TestCollectSATADrives_UnknownProtocol covers nvme_linux.go:310 — the default
// case when the protocol doesn't match ata/sata/scsi/sas: Type = proto.
func TestCollectSATADrives_UnknownProtocol(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--scan-open", "--json=c"},
			`{"devices":[{"name":"/dev/sda","protocol":"USB","open_error":"Permission denied"}]}`, 0)
	})
	info := &models.NVMeInfo{}
	collectSATADrives(context.Background(), info)
	if len(info.SATADevices) != 1 {
		t.Fatalf("SATADevices = %+v, want 1 for USB protocol device", info.SATADevices)
	}
	if info.SATADevices[0].Type != "usb" {
		t.Errorf("Type = %q, want usb (protocol lowercased via default case)", info.SATADevices[0].Type)
	}
}

// TestApplySATASmartJSON_ATAAttribute197 covers nvme_linux.go:404 — case 197
// (pending-sector count) in the ATA smart attributes switch.
func TestApplySATASmartJSON_ATAAttribute197(t *testing.T) {
	t.Parallel()
	var d models.SATADevice
	applySATASmartJSON(`{"smart_status":{"passed":true},"ata_smart_attributes":{"table":[{"id":197,"raw":{"value":3}}]}}`, &d)
	if d.PendingSectors != 3 {
		t.Errorf("PendingSectors = %d, want 3 (ATA attribute ID 197)", d.PendingSectors)
	}
}

// TestParseInt64_EmptyAndGarbled guards parseInt64's empty-fields short-circuit
// directly — parseNVMeSmartLog callers only ever exercise the happy path.
func TestParseInt64_EmptyAndGarbled(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want int64
	}{
		{"empty string", "", 0},
		{"whitespace only", "  ", 0},
		{"garbled non-numeric", "xyz", 0},
		{"negative", "-1", 0},
		{"valid", "1234", 1234},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := parseInt64(c.in); got != c.want {
				t.Errorf("parseInt64(%q) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}
