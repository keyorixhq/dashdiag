//go:build linux

package collectors

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestHBACollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewHBACollector()
	if c.Name() != "HBA" {
		t.Errorf("Name() = %q, want HBA", c.Name())
	}
	if c.Timeout() <= 0 {
		t.Errorf("Timeout() = %v, want > 0", c.Timeout())
	}
}

// TestHBACollector_Collect_NoHosts guards the no-hardware case: an empty (or
// erroring) glob leaves info.Ports nil but Collect still returns a non-nil
// *models.HBAInfo rather than gating off to nil.
func TestHBACollector_Collect_NoHosts(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/fc_host/host*", nil)
	})
	c := NewHBACollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.HBAInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.HBAInfo", raw)
	}
	if len(info.Ports) != 0 {
		t.Errorf("Ports = %+v, want empty", info.Ports)
	}
}

// TestHBACollector_Collect_OneHost exercises the full glob -> readHBAPort
// path end to end, including the driver-symlink parse.
func TestHBACollector_Collect_OneHost(t *testing.T) {
	host := "/sys/class/fc_host/host0"
	withCombinedFixture(t, nil, map[string]string{
		host: "../../devices/pci0000:00/0000:00:03.0/0000:03:00.0/host0/fc_host/lpfc/host0",
	}, func(b *source.Bundle) {
		b.PutGlob("/sys/class/fc_host/host*", []string{host})
		b.PutFile(host+"/port_state", []byte("Online\n"))
		b.PutFile(host+"/node_name", []byte("0x2000f4e9d456789a\n"))
		b.PutFile(host+"/port_name", []byte("0x2100f4e9d456789a\n"))
		b.PutFile(host+"/fabric_name", []byte("0x2000000c50a1b2c3\n"))
		b.PutFile(host+"/speed", []byte("16 Gbit\n"))
		b.PutFile(host+"/statistics/link_failure_count", []byte("0x2f\n"))
		b.PutFile(host+"/statistics/loss_of_sync_count", []byte("0x0\n"))
		b.PutFile(host+"/statistics/loss_of_signal_count", []byte("0x0\n"))
	})
	c := NewHBACollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HBAInfo)
	if len(info.Ports) != 1 {
		t.Fatalf("Ports = %+v, want exactly 1", info.Ports)
	}
	p := info.Ports[0]
	if p.Name != "host0" {
		t.Errorf("Name = %q, want host0", p.Name)
	}
	if p.PortState != "Online" || p.SpeedGbps != 16 {
		t.Errorf("PortState/SpeedGbps = %q/%d, want Online/16", p.PortState, p.SpeedGbps)
	}
	if p.LinkFailures != 47 {
		t.Errorf("LinkFailures = %d, want 47", p.LinkFailures)
	}
	if p.Driver != "lpfc" {
		t.Errorf("Driver = %q, want lpfc", p.Driver)
	}
}

func TestIsHBAPresent(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/sys/class/fc_host/host*", []string{"/sys/class/fc_host/host0"})
		})
		if !IsHBAPresent() {
			t.Error("IsHBAPresent() = false, want true")
		}
	})
	t.Run("absent", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/sys/class/fc_host/host*", nil)
		})
		if IsHBAPresent() {
			t.Error("IsHBAPresent() = true, want false")
		}
	})
}

// TestReadHBAPort_NoSymlink guards the readLink error branch: when the
// symlink target can't be resolved (nonexistent path — not seeded into any
// fixture, so readLink() errors), Driver must stay empty rather than
// panicking or reading a garbled value.
func TestReadHBAPort_NoSymlink(t *testing.T) {
	hostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hostDir, "port_state"), []byte("Linkdown\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	port := readHBAPort(hostDir)
	if port.Driver != "" {
		t.Errorf("Driver = %q, want empty (no symlink present)", port.Driver)
	}
	if port.PortState != "Linkdown" {
		t.Errorf("PortState = %q, want Linkdown", port.PortState)
	}
}

func TestReadSysfsInt(t *testing.T) {
	t.Run("valid decimal", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/sys/class/fc_host/host0/some_counter", []byte("42\n"))
		})
		if got := readSysfsInt("/sys/class/fc_host/host0/some_counter"); got != 42 {
			t.Errorf("readSysfsInt() = %d, want 42", got)
		}
	})
	t.Run("missing file returns 0", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		if got := readSysfsInt("/sys/class/fc_host/host0/some_counter"); got != 0 {
			t.Errorf("readSysfsInt() = %d, want 0", got)
		}
	})
}

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
