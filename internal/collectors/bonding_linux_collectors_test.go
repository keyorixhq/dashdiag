//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestNewBondingCollectorIdentity guards the collector's Name/Timeout wiring —
// registry code depends on Name() for output labeling and Timeout() for the
// per-collector context deadline the runner derives.
func TestNewBondingCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewBondingCollector()
	if c == nil {
		t.Fatal("NewBondingCollector() returned nil")
	}
	if c.Name() != "Bonding" {
		t.Errorf("Name() = %q, want Bonding", c.Name())
	}
	if c.Timeout() != 3*time.Second {
		t.Errorf("Timeout() = %v, want 3s", c.Timeout())
	}
}

// TestBondingCollector_Collect_NoBonds guards the common no-bonding-present host:
// no /proc/net/bonding/bond* files at all must return an empty (not nil) info
// with zero bonds, not an error.
func TestBondingCollector_Collect_NoBonds(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // no bond files seeded

	c := NewBondingCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.BondingInfo)
	if !ok {
		t.Fatalf("unexpected type %T", raw)
	}
	if len(info.Bonds) != 0 {
		t.Errorf("expected no bonds, got %+v", info.Bonds)
	}
}

// TestBondingCollector_Collect_SingleBond exercises the happy path: one bond
// file present via PutGlob+PutFile must be parsed and appended to info.Bonds.
func TestBondingCollector_Collect_SingleBond(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/proc/net/bonding/bond*", []string{"/proc/net/bonding/bond0"})
		b.PutFile("/proc/net/bonding/bond0", []byte(
			"Ethernet Channel Bonding Driver: v6.6.0\n"+
				"\n"+
				"Bonding Mode: fault-tolerance (active-backup)\n"+
				"Currently Active Slave: eth0\n"+
				"\n"+
				"Slave Interface: eth0\n"+
				"MII Status: up\n"+
				"Speed: 1000 Mbps\n",
		))
	})

	c := NewBondingCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.BondingInfo)
	if len(info.Bonds) != 1 {
		t.Fatalf("expected 1 bond, got %d: %+v", len(info.Bonds), info.Bonds)
	}
	if info.Bonds[0].Name != "bond0" || info.Bonds[0].ActiveSlave != "eth0" {
		t.Errorf("unexpected bond parsed: %+v", info.Bonds[0])
	}
}

// TestBondingCollector_Collect_UnreadableBondSkipped guards the per-file error
// tolerance: a glob match that can't actually be read (recording gap /
// permission error) must be skipped rather than failing the whole collector,
// so one bad bond file doesn't blank out every other bond's data.
func TestBondingCollector_Collect_UnreadableBondSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/proc/net/bonding/bond*", []string{
			"/proc/net/bonding/bond0",
			"/proc/net/bonding/bond1",
		})
		// bond0 deliberately NOT seeded via PutFile -> ReadFile returns
		// ErrNotRecorded, exercising the `continue` skip branch.
		b.PutFile("/proc/net/bonding/bond1", []byte(
			"Bonding Mode: fault-tolerance (active-backup)\n"+
				"Slave Interface: eth2\n"+
				"MII Status: up\n",
		))
	})

	c := NewBondingCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.BondingInfo)
	if len(info.Bonds) != 1 || info.Bonds[0].Name != "bond1" {
		t.Errorf("expected only bond1 to survive the unreadable bond0, got %+v", info.Bonds)
	}
}

// TestIsBondingPresent guards the true/false gate used elsewhere (e.g. dsd net).
func TestIsBondingPresent(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/proc/net/bonding/bond*", []string{"/proc/net/bonding/bond0"})
		})
		if !IsBondingPresent() {
			t.Error("expected true when a bond glob match exists")
		}
	})

	t.Run("absent", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if IsBondingPresent() {
			t.Error("expected false when no bond files exist")
		}
	})
}

// TestCollectBonds guards the NetworkCollector-facing helper: same glob+parse
// logic as BondingCollector.Collect, but returning a plain slice.
func TestCollectBonds(t *testing.T) {
	t.Run("no bonds returns nil", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if bonds := collectBonds(); bonds != nil {
			t.Errorf("expected nil, got %+v", bonds)
		}
	})

	t.Run("parses bond and skips unreadable", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/proc/net/bonding/bond*", []string{
				"/proc/net/bonding/bond0",
				"/proc/net/bonding/bond1",
			})
			b.PutFile("/proc/net/bonding/bond0", []byte(
				"Bonding Mode: fault-tolerance (active-backup)\n"+
					"Slave Interface: eth0\n"+
					"MII Status: down\n",
			))
			// bond1 not seeded -> skipped
		})
		bonds := collectBonds()
		if len(bonds) != 1 || bonds[0].Name != "bond0" {
			t.Fatalf("expected only bond0, got %+v", bonds)
		}
		if !bonds[0].AllDown {
			t.Errorf("expected AllDown=true (sole slave down), got %+v", bonds[0])
		}
	})
}
