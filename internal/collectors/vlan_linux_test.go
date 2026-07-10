//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// NOTE: withFixtureSource swaps a package-level global (activeSource) — these
// tests deliberately do NOT call t.Parallel(), matching the established
// convention in security_linux_source_test.go / nginx_linux_test.go.

func TestVLANCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewVLANCollector()
	if c.Name() != "VLAN" {
		t.Errorf("Name() = %q, want VLAN", c.Name())
	}
	if c.Timeout() != 3*time.Second {
		t.Errorf("Timeout() = %v, want 3s", c.Timeout())
	}
}

func TestIsVLANPresent(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			// fileExists()/statFile() needs an explicit PutStat — PutFile alone only
			// seeds ReadFile, not Stat (see source.Replay.Stat / getStat).
			b.PutStat("/proc/net/vlan/config", source.FileMeta{Mode: 0o644})
			b.PutFile("/proc/net/vlan/config", []byte("VLAN Dev name    | VLAN ID\nName-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\neth0.100      | 100  | eth0\n"))
		})
		if !IsVLANPresent() {
			t.Error("IsVLANPresent() = false, want true")
		}
	})
	t.Run("absent", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if IsVLANPresent() {
			t.Error("IsVLANPresent() = true, want false")
		}
	})
}

// TestVLANCollector_Collect_ConfigAbsent guards the 8021q-module-not-loaded
// gate: the config file simply doesn't exist -> nil,nil (section absent, no
// phantom "VLAN OK" row).
func TestVLANCollector_Collect_ConfigAbsent(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {})
	c := NewVLANCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("raw = %+v, want nil (config absent -> section absent)", raw)
	}
}

// TestVLANCollector_Collect_ConfigPresentNoInterfaces guards the "8021q
// loaded but zero VLAN interfaces configured" gate: config exists with only
// header lines -> nil,nil (still absent, not an empty-but-present VLANInfo).
func TestVLANCollector_Collect_ConfigPresentNoInterfaces(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/vlan/config", []byte(
			"VLAN Dev name    | VLAN ID\n"+
				"Name-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\n"))
	})
	c := NewVLANCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("raw = %+v, want nil (no VLAN interfaces -> section absent)", raw)
	}
}

// TestVLANCollector_Collect_HappyPath exercises the full parse path. The
// interface name won't resolve via net.InterfaceByName inside the test
// sandbox, so Up is deterministically false — that's the real, un-mocked
// net package (VLANCollector.Collect does not route interface lookup through
// activeSource), and is asserted explicitly rather than left implicit.
func TestVLANCollector_Collect_HappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/vlan/config", []byte(
			"VLAN Dev name    | VLAN ID\n"+
				"Name-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\n"+
				"eth0.100      | 100  | eth0\n"+
				"eth0.200      | 200  | eth0\n"))
	})
	c := NewVLANCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.VLANInfo)
	if !ok {
		t.Fatalf("raw = %+v (%T), want *models.VLANInfo", raw, raw)
	}
	if len(info.Interfaces) != 2 {
		t.Fatalf("Interfaces = %+v, want 2", info.Interfaces)
	}
	if info.Interfaces[0].Name != "eth0.100" || info.Interfaces[0].VLANID != 100 || info.Interfaces[0].Parent != "eth0" {
		t.Errorf("Interfaces[0] = %+v, want name=eth0.100 vlanid=100 parent=eth0", info.Interfaces[0])
	}
	if info.Interfaces[0].Up {
		t.Error("Interfaces[0].Up = true, want false (interface does not exist on the test sandbox)")
	}
	if info.Interfaces[1].Name != "eth0.200" || info.Interfaces[1].VLANID != 200 {
		t.Errorf("Interfaces[1] = %+v, want name=eth0.200 vlanid=200", info.Interfaces[1])
	}
}

// TestVLANCollector_Collect_SkipsHeaderAndMalformedLines guards the
// "Name"/"---" prefix skip and the < 3 pipe-fields skip in the same pass as
// a real line, so a malformed row can't silently produce a bogus interface.
func TestVLANCollector_Collect_SkipsHeaderAndMalformedLines(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/vlan/config", []byte(
			"Name-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\n"+
				"--------------------\n"+
				"malformed line no pipes\n"+
				"eth0.100      | 100  | eth0\n"))
	})
	c := NewVLANCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VLANInfo)
	if len(info.Interfaces) != 1 || info.Interfaces[0].Name != "eth0.100" {
		t.Errorf("Interfaces = %+v, want exactly the one well-formed eth0.100 row", info.Interfaces)
	}
}

// NOTE: parseVLANConfig already has a dedicated parser test
// (TestParseVLANConfig) in medium_low_linux_test.go — not duplicated here.
