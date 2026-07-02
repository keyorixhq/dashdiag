//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadSysfsHexInt is a regression guard: the kernel SCSI FC transport class
// formats fc_host statistics/* counters ALWAYS as hex with a "0x" prefix
// (fc_host_statistic, "0x%llx\n") — a plain decimal Atoi (readSysfsInt) silently
// parses every one of these as 0, so the flapping-link WARN could never fire.
func TestReadSysfsHexInt(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    int
	}{
		{"healthy zero", "0x0\n", 0},
		{"flapping link", "0x2f\n", 47},
		{"uppercase prefix", "0X10\n", 16},
		{"large counter", "0xffff\n", 65535},
		{"no trailing newline", "0x7", 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "counter")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			if got := readSysfsHexInt(path); got != tc.want {
				t.Errorf("readSysfsHexInt(%q) = %d, want %d", tc.content, got, tc.want)
			}
		})
	}

	// Missing file must not panic and must read as 0, not crash the collector.
	if got := readSysfsHexInt(filepath.Join(t.TempDir(), "missing")); got != 0 {
		t.Errorf("missing file: got %d, want 0", got)
	}
}

// TestReadHBAPort_HexCounters exercises the full readHBAPort path against a
// real fc_host sysfs layout (as far as file content goes) with hex-formatted
// error counters, proving LinkFailures/LossOfSync/LossOfSignal are no longer
// silently zeroed.
func TestReadHBAPort_HexCounters(t *testing.T) {
	hostDir := t.TempDir()
	statsDir := filepath.Join(hostDir, "statistics")
	if err := os.MkdirAll(statsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"port_state":                      "Online\n",
		"node_name":                       "0x2000f4e9d456789a\n",
		"port_name":                       "0x2100f4e9d456789a\n",
		"fabric_name":                     "0x2000000c50a1b2c3\n",
		"speed":                           "16 Gbit\n",
		"statistics/link_failure_count":   "0x2f\n",
		"statistics/loss_of_sync_count":   "0x69\n",
		"statistics/loss_of_signal_count": "0x0\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(hostDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	port := readHBAPort(hostDir)
	if port.LinkFailures != 47 {
		t.Errorf("LinkFailures = %d, want 47 (0x2f)", port.LinkFailures)
	}
	if port.LossOfSync != 105 {
		t.Errorf("LossOfSync = %d, want 105 (0x69)", port.LossOfSync)
	}
	if port.LossOfSignal != 0 {
		t.Errorf("LossOfSignal = %d, want 0", port.LossOfSignal)
	}
	if port.PortState != "Online" {
		t.Errorf("PortState = %q, want Online", port.PortState)
	}
	if port.SpeedGbps != 16 {
		t.Errorf("SpeedGbps = %d, want 16", port.SpeedGbps)
	}
}
