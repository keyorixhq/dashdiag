//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestNewSRIOVCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewSRIOVCollector()
	if c.Name() != "SRIOV" {
		t.Errorf("Name() = %q, want SRIOV", c.Name())
	}
	if got := c.Timeout(); got != 3*time.Second {
		t.Errorf("Timeout() = %v, want 3s", got)
	}
}

// TestSRIOVCollector_Collect_NoDevices guards the gate-off case: no
// sriov_numvfs files at all -> Collect returns an empty (non-nil) info with
// no Devices.
func TestSRIOVCollector_Collect_NoDevices(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/bus/pci/devices/*/sriov_numvfs", nil)
	})
	c := NewSRIOVCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info, ok := raw.(*models.SRIOVInfo)
	if !ok {
		t.Fatalf("unexpected type %T", raw)
	}
	if len(info.Devices) != 0 {
		t.Errorf("Devices = %+v, want empty", info.Devices)
	}
}

// TestSRIOVCollector_Collect_TotalVFsZeroSkipped guards the "capable but
// zero total VFs" filter: a device that shows up in the sriov_numvfs glob
// but reports sriov_totalvfs=0 must be excluded from the results.
func TestSRIOVCollector_Collect_TotalVFsZeroSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/bus/pci/devices/*/sriov_numvfs", []string{
			"/sys/bus/pci/devices/0000:01:00.0/sriov_numvfs",
		})
		b.PutFile("/sys/bus/pci/devices/0000:01:00.0/sriov_numvfs", []byte("0\n"))
		b.PutFile("/sys/bus/pci/devices/0000:01:00.0/sriov_totalvfs", []byte("0\n"))
	})
	c := NewSRIOVCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info := raw.(*models.SRIOVInfo) //nolint:errcheck // type asserted in sibling test
	if len(info.Devices) != 0 {
		t.Errorf("Devices = %+v, want empty (totalvfs=0 devices must be skipped)", info.Devices)
	}
}

// TestSRIOVCollector_Collect_DeviceWithVFs exercises a real SR-IOV-capable
// device with VFs enabled — driver resolution is NOT source-routed
// (filepath.EvalSymlinks hits the real filesystem, which won't find the
// fixture path), so Driver is expected to end up empty in this test; that's
// documented in the report, not asserted as a bug.
func TestSRIOVCollector_Collect_DeviceWithVFs(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/bus/pci/devices/*/sriov_numvfs", []string{
			"/sys/bus/pci/devices/0000:01:00.0/sriov_numvfs",
		})
		b.PutFile("/sys/bus/pci/devices/0000:01:00.0/sriov_numvfs", []byte("4\n"))
		b.PutFile("/sys/bus/pci/devices/0000:01:00.0/sriov_totalvfs", []byte("8\n"))
	})
	c := NewSRIOVCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info := raw.(*models.SRIOVInfo) //nolint:errcheck // type asserted in sibling test
	if len(info.Devices) != 1 {
		t.Fatalf("Devices = %+v, want exactly 1", info.Devices)
	}
	dev := info.Devices[0]
	if dev.PCI != "0000:01:00.0" {
		t.Errorf("PCI = %q, want 0000:01:00.0", dev.PCI)
	}
	if dev.NumVFs != 4 || dev.TotalVFs != 8 {
		t.Errorf("NumVFs/TotalVFs = %d/%d, want 4/8", dev.NumVFs, dev.TotalVFs)
	}
}

// TestSRIOVCollector_Collect_MultipleDevices guards that more than one
// SR-IOV-capable device is aggregated, and that a zero-totalvfs device mixed
// in with real ones is still filtered out individually.
func TestSRIOVCollector_Collect_MultipleDevices(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/bus/pci/devices/*/sriov_numvfs", []string{
			"/sys/bus/pci/devices/0000:01:00.0/sriov_numvfs",
			"/sys/bus/pci/devices/0000:02:00.0/sriov_numvfs",
		})
		b.PutFile("/sys/bus/pci/devices/0000:01:00.0/sriov_numvfs", []byte("2\n"))
		b.PutFile("/sys/bus/pci/devices/0000:01:00.0/sriov_totalvfs", []byte("16\n"))
		b.PutFile("/sys/bus/pci/devices/0000:02:00.0/sriov_numvfs", []byte("0\n"))
		b.PutFile("/sys/bus/pci/devices/0000:02:00.0/sriov_totalvfs", []byte("0\n"))
	})
	c := NewSRIOVCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info := raw.(*models.SRIOVInfo) //nolint:errcheck // type asserted in sibling test
	if len(info.Devices) != 1 {
		t.Fatalf("Devices = %+v, want exactly 1 (second device has totalvfs=0)", info.Devices)
	}
	if info.Devices[0].PCI != "0000:01:00.0" {
		t.Errorf("PCI = %q, want 0000:01:00.0", info.Devices[0].PCI)
	}
}

func TestIsSRIOVPresent(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/sys/bus/pci/devices/*/sriov_totalvfs", []string{
				"/sys/bus/pci/devices/0000:01:00.0/sriov_totalvfs",
			})
			b.PutFile("/sys/bus/pci/devices/0000:01:00.0/sriov_totalvfs", []byte("8\n"))
		})
		if !IsSRIOVPresent() {
			t.Error("expected true when a device reports totalvfs > 0")
		}
	})
	t.Run("absent - no devices", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/sys/bus/pci/devices/*/sriov_totalvfs", nil)
		})
		if IsSRIOVPresent() {
			t.Error("expected false when no sriov_totalvfs files exist")
		}
	})
	t.Run("absent - all zero", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/sys/bus/pci/devices/*/sriov_totalvfs", []string{
				"/sys/bus/pci/devices/0000:01:00.0/sriov_totalvfs",
			})
			b.PutFile("/sys/bus/pci/devices/0000:01:00.0/sriov_totalvfs", []byte("0\n"))
		})
		if IsSRIOVPresent() {
			t.Error("expected false when totalvfs is 0")
		}
	})
	t.Run("unparseable value", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/sys/bus/pci/devices/*/sriov_totalvfs", []string{
				"/sys/bus/pci/devices/0000:01:00.0/sriov_totalvfs",
			})
			b.PutFile("/sys/bus/pci/devices/0000:01:00.0/sriov_totalvfs", []byte("garbage\n"))
		})
		if IsSRIOVPresent() {
			t.Error("expected false for an unparseable totalvfs value")
		}
	})
}
