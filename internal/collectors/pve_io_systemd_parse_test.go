//go:build linux

package collectors

import (
	"strconv"
	"testing"
	"time"
)

// TestParsePVEBackupTasks guards the backup-freshness derivation: only tasks
// within the last 7 days are kept in the returned list, ageDays reflects the
// most recent OK (successful) task regardless of window, and byVM tracks the
// latest OK per-VM timestamp for the per-VM audit.
func TestParsePVEBackupTasks(t *testing.T) {
	recentOK := time.Now().Add(-1 * 24 * time.Hour)
	oldOK := time.Now().Add(-10 * 24 * time.Hour)
	itoa := func(n int64) string { return strconv.FormatInt(n, 10) }
	out := `[
		{"id":"100","status":"OK","endtime":` + itoa(recentOK.Unix()) + `},
		{"id":"101","status":"ERROR","endtime":` + itoa(recentOK.Unix()) + `},
		{"id":"100","status":"OK","endtime":` + itoa(oldOK.Unix()) + `}
	]`
	tasks, ageDays, byVM := parsePVEBackupTasks(out)

	if len(tasks) != 2 {
		t.Errorf("expected 2 tasks within the 7-day window (the old OK task excluded), got %d: %+v", len(tasks), tasks)
	}
	if ageDays != 1 {
		t.Errorf("ageDays should reflect the most recent OK task (~1 day ago), got %d", ageDays)
	}
	if byVM[100].Unix() != recentOK.Unix() {
		t.Errorf("byVM[100] should track the LATEST OK timestamp for that VM, got %v", byVM[100])
	}
}

func TestParsePVEBackupTasksMalformed(t *testing.T) {
	_, ageDays, byVM := parsePVEBackupTasks("not json")
	if ageDays != -1 || byVM != nil {
		t.Errorf("malformed JSON should return ageDays=-1 and a nil map, got ageDays=%d byVM=%v", ageDays, byVM)
	}
}

func TestComputeDelta(t *testing.T) {
	before := diskStatRaw{reads: 100, writes: 50, readSectors: 2000, writeSectors: 1000, readTimeMs: 500, writeTimeMs: 300, ioTimeMs: 200}
	after := diskStatRaw{reads: 110, writes: 55, readSectors: 3000, writeSectors: 1500, readTimeMs: 700, writeTimeMs: 400, ioTimeMs: 1200}

	dev := computeDelta("nvme0n1", before, after)
	if dev.DriveType != "nvme" {
		t.Errorf("an nvme-prefixed device name should be classified as nvme, got %q", dev.DriveType)
	}
	// readSectors delta 1000 * 512 bytes / 1e6 = 0.512 MB/s
	if dev.ReadMBps != 0.512 {
		t.Errorf("ReadMBps = %v, want 0.512", dev.ReadMBps)
	}
	// ioTimeMs delta 1000ms / 10 = 100% util
	if dev.UtilPct != 100 {
		t.Errorf("UtilPct should clamp at 100, got %v", dev.UtilPct)
	}
	// ops delta = (110+55)-(100+50) = 15; time delta = (700+400)-(500+300) = 300ms; await = 300/15 = 20ms
	if dev.AwaitMs != 20 {
		t.Errorf("AwaitMs = %v, want 20", dev.AwaitMs)
	}
}

// TestComputeDeltaCounterReset guards against a counter that appears to go
// backwards (device reset/hotplug mid-sample) producing a wrapped huge delta
// instead of a safe zero.
func TestComputeDeltaCounterReset(t *testing.T) {
	before := diskStatRaw{readSectors: 5000, ioTimeMs: 900}
	after := diskStatRaw{readSectors: 100, ioTimeMs: 50} // counters reset
	dev := computeDelta("sda", before, after)
	if dev.ReadMBps != 0 {
		t.Errorf("a reset read-sectors counter must floor at 0, not wrap to a huge delta, got %v", dev.ReadMBps)
	}
	if dev.UtilPct != 0 {
		t.Errorf("a reset ioTimeMs counter must floor at 0, got %v", dev.UtilPct)
	}
}

func TestIOParseFloat(t *testing.T) {
	if got := parseFloat("12.5"); got != 12.5 {
		t.Errorf("parseFloat(12.5) = %v", got)
	}
	if got := parseFloat("not a number"); got != 0 {
		t.Errorf("an unparseable string should return 0, got %v", got)
	}
}

func TestParseAnalyzeTime(t *testing.T) {
	// Real systemd-analyze output: "Startup finished in 3.456s (kernel) + 1min 2.000s (userspace) = 1min 5.456s"
	out := "Startup finished in 3.456s (kernel) + 1min 2.000s (userspace) = 1min 5.456s"
	if got := parseAnalyzeTime(out); got != 65.456 {
		t.Errorf("parseAnalyzeTime should extract the total after the last '=', got %v", got)
	}
	if got := parseAnalyzeTime("no equals sign here"); got != 0 {
		t.Errorf("output with no '=' should return 0, got %v", got)
	}
}

func TestParseNginxVersion(t *testing.T) {
	if got := parseNginxVersion("nginx version: nginx/1.27.0\nbuilt with OpenSSL 3.0\n"); got != "1.27.0" {
		t.Errorf("parseNginxVersion should extract the version after nginx/, got %q", got)
	}
	if got := parseNginxVersion("garbage output"); got != "" {
		t.Errorf("output without the nginx/ marker should return empty, got %q", got)
	}
}
