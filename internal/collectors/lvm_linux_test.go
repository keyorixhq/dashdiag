//go:build linux

package collectors

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestLVMCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewLVMCollector()
	if c.Name() != "LVM" {
		t.Errorf("Name() = %q, want LVM", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

func TestIsLVMPresent(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("lvs", []string{"--version"}, "  LVM version:     2.03.11(2)\n", 0)
		})
		if !IsLVMPresent() {
			t.Error("expected true when lvs --version succeeds")
		}
	})

	t.Run("absent", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmdNotFound("lvs", []string{"--version"})
		})
		if IsLVMPresent() {
			t.Error("expected false when lvs is not installed")
		}
	})
}

// TestLVMCollector_Collect_NotDetected guards the gate-off path: when lvm2 is
// not installed, Collect must return an empty LVMInfo{} without running any
// further vgs/pvs/lvs commands.
func TestLVMCollector_Collect_NotDetected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("lvs", []string{"--version"})
	})
	c := NewLVMCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.LVMInfo)
	if !reflect.DeepEqual(info, &models.LVMInfo{}) {
		t.Errorf("expected empty LVMInfo{} when lvm2 absent, got %+v", info)
	}
}

// TestLVMCollector_Collect_HappyPath exercises the full path: vgs/pvs/lvs/raid
// all succeed, plus /proc/mounts for mergeMountedLVs.
func TestLVMCollector_Collect_HappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("lvs", []string{"--version"}, "  LVM version:     2.03.11(2)\n", 0)
		b.PutCmd("vgs", []string{"--noheadings", "--nosuffix", "--units", "g", "-o", "vg_name,vg_size,vg_free,vg_attr"},
			"  ol   50.00 10.00 wz--n-\n", 0)
		b.PutCmd("pvs", []string{"--noheadings", "-o", "vg_name,pv_attr"},
			"  ol a--\n", 0)
		b.PutCmd("lvs", []string{"--noheadings", "--nosuffix", "--units", "g",
			"-o", "lv_name,vg_name,lv_attr,data_percent,metadata_percent,origin,lv_size"},
			"  root ol -wi-ao---- 20.00\n", 0)
		b.PutCmd("lvs", []string{"--noheadings", "--nosuffix", "--units", "g",
			"-o", "lv_name,vg_name,lv_attr,lv_size,copy_percent"},
			"  root ol rwi-aor--- 20.00 100.00\n", 0)
		b.PutFile("/proc/mounts", []byte("/dev/mapper/ol-root / ext4 rw,relatime 0 0\n"))
	})

	c := NewLVMCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.LVMInfo)

	if info.VGReadFailed || info.PVReadFailed || info.LVReadFailed || info.RaidReadFailed {
		t.Errorf("no reads should have failed, got %+v", info)
	}
	if len(info.VGs) != 1 || info.VGs[0].Name != "ol" {
		t.Fatalf("VGs = %+v, want one VG named ol", info.VGs)
	}
	if !info.VGs[0].HasMountedLV {
		t.Errorf("VG ol should be marked HasMountedLV via /proc/mounts, got %+v", info.VGs[0])
	}
	if len(info.RaidLVs) != 1 || info.RaidLVs[0].Name != "root" {
		t.Fatalf("RaidLVs = %+v, want one raid LV named root", info.RaidLVs)
	}
}

func TestLVMCollector_Collect_VGReadFailed(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("lvs", []string{"--version"}, "  LVM version:     2.03.11(2)\n", 0)
		b.PutCmd("vgs", []string{"--noheadings", "--nosuffix", "--units", "g", "-o", "vg_name,vg_size,vg_free,vg_attr"},
			"", 1)
		b.PutCmd("pvs", []string{"--noheadings", "-o", "vg_name,pv_attr"}, "", 0)
		b.PutCmd("lvs", []string{"--noheadings", "--nosuffix", "--units", "g",
			"-o", "lv_name,vg_name,lv_attr,data_percent,metadata_percent,origin,lv_size"}, "", 0)
		b.PutCmd("lvs", []string{"--noheadings", "--nosuffix", "--units", "g",
			"-o", "lv_name,vg_name,lv_attr,lv_size,copy_percent"}, "", 0)
	})
	c := NewLVMCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.LVMInfo)
	if !info.VGReadFailed {
		t.Error("expected VGReadFailed=true when vgs fails")
	}
	if info.PVReadFailed || info.LVReadFailed || info.RaidReadFailed {
		t.Errorf("only VGReadFailed should be set, got %+v", info)
	}
}

func TestLVMCollector_Collect_PVReadFailed(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("lvs", []string{"--version"}, "  LVM version:     2.03.11(2)\n", 0)
		b.PutCmd("vgs", []string{"--noheadings", "--nosuffix", "--units", "g", "-o", "vg_name,vg_size,vg_free,vg_attr"}, "", 0)
		b.PutCmd("pvs", []string{"--noheadings", "-o", "vg_name,pv_attr"}, "", 1)
		b.PutCmd("lvs", []string{"--noheadings", "--nosuffix", "--units", "g",
			"-o", "lv_name,vg_name,lv_attr,data_percent,metadata_percent,origin,lv_size"}, "", 0)
		b.PutCmd("lvs", []string{"--noheadings", "--nosuffix", "--units", "g",
			"-o", "lv_name,vg_name,lv_attr,lv_size,copy_percent"}, "", 0)
	})
	c := NewLVMCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.LVMInfo)
	if !info.PVReadFailed {
		t.Error("expected PVReadFailed=true when pvs fails")
	}
	if info.VGReadFailed || info.LVReadFailed || info.RaidReadFailed {
		t.Errorf("only PVReadFailed should be set, got %+v", info)
	}
}

func TestLVMCollector_Collect_LVReadFailed(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("lvs", []string{"--version"}, "  LVM version:     2.03.11(2)\n", 0)
		b.PutCmd("vgs", []string{"--noheadings", "--nosuffix", "--units", "g", "-o", "vg_name,vg_size,vg_free,vg_attr"}, "", 0)
		b.PutCmd("pvs", []string{"--noheadings", "-o", "vg_name,pv_attr"}, "", 0)
		b.PutCmd("lvs", []string{"--noheadings", "--nosuffix", "--units", "g",
			"-o", "lv_name,vg_name,lv_attr,data_percent,metadata_percent,origin,lv_size"}, "", 1)
		b.PutCmd("lvs", []string{"--noheadings", "--nosuffix", "--units", "g",
			"-o", "lv_name,vg_name,lv_attr,lv_size,copy_percent"}, "", 0)
	})
	c := NewLVMCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.LVMInfo)
	if !info.LVReadFailed {
		t.Error("expected LVReadFailed=true when the thin/snapshot lvs query fails")
	}
	if info.VGReadFailed || info.PVReadFailed || info.RaidReadFailed {
		t.Errorf("only LVReadFailed should be set, got %+v", info)
	}
}

func TestLVMCollector_Collect_RaidReadFailed(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("lvs", []string{"--version"}, "  LVM version:     2.03.11(2)\n", 0)
		b.PutCmd("vgs", []string{"--noheadings", "--nosuffix", "--units", "g", "-o", "vg_name,vg_size,vg_free,vg_attr"}, "", 0)
		b.PutCmd("pvs", []string{"--noheadings", "-o", "vg_name,pv_attr"}, "", 0)
		b.PutCmd("lvs", []string{"--noheadings", "--nosuffix", "--units", "g",
			"-o", "lv_name,vg_name,lv_attr,data_percent,metadata_percent,origin,lv_size"}, "", 0)
		b.PutCmd("lvs", []string{"--noheadings", "--nosuffix", "--units", "g",
			"-o", "lv_name,vg_name,lv_attr,lv_size,copy_percent"}, "", 1)
	})
	c := NewLVMCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.LVMInfo)
	if !info.RaidReadFailed {
		t.Error("expected RaidReadFailed=true when the raid lvs query fails")
	}
	if info.VGReadFailed || info.PVReadFailed || info.LVReadFailed {
		t.Errorf("only RaidReadFailed should be set, got %+v", info)
	}
}

// TestParseLVMRaid extends the existing 40.9%-covered parser test to hit the
// mirror/raid lvType branches, degraded/resyncing flags, missing copy_percent
// default, short attr string, and too-few-fields skip.
func TestParseLVMRaid(t *testing.T) {
	t.Parallel()
	t.Run("mirror lvType", func(t *testing.T) {
		t.Parallel()
		got := parseLVMRaid("  mirror1 vg0 mwi-a-m--- 5.00 100.00\n")
		if len(got) != 1 || got[0].Type != "mirror" {
			t.Fatalf("got %+v, want a single mirror LV", got)
		}
	})

	t.Run("raid lvType", func(t *testing.T) {
		t.Parallel()
		got := parseLVMRaid("  raid1lv vg0 rwi-a-r--- 5.00 100.00\n")
		if len(got) != 1 || got[0].Type != "raid" {
			t.Fatalf("got %+v, want a single raid LV", got)
		}
	})

	t.Run("degraded flag attr[8]=='p'", func(t *testing.T) {
		t.Parallel()
		got := parseLVMRaid("  raid1lv vg0 rwi-a---p- 5.00 42.00\n")
		if len(got) != 1 || !got[0].Degraded {
			t.Fatalf("got %+v, want Degraded=true", got)
		}
	})

	t.Run("resyncing flag attr[9]=='r'", func(t *testing.T) {
		t.Parallel()
		got := parseLVMRaid("  raid1lv vg0 rwi-a----r 5.00 55.00\n")
		if len(got) != 1 || !got[0].Resyncing {
			t.Fatalf("got %+v, want Resyncing=true", got)
		}
	})

	t.Run("missing copy_percent defaults to 100.0", func(t *testing.T) {
		t.Parallel()
		got := parseLVMRaid("  raid1lv vg0 rwi-a-r--- 5.00\n")
		if len(got) != 1 || got[0].SyncPct != 100.0 {
			t.Fatalf("got %+v, want SyncPct=100.0 when copy_percent absent", got)
		}
	})

	t.Run("empty copy_percent field defaults to 100.0", func(t *testing.T) {
		t.Parallel()
		got := parseLVMRaid("  raid1lv vg0 rwi-a-r--- 5.00 \n")
		if len(got) != 1 || got[0].SyncPct != 100.0 {
			t.Fatalf("got %+v, want SyncPct=100.0 when copy_percent is blank", got)
		}
	})

	t.Run("short attr string skipped", func(t *testing.T) {
		t.Parallel()
		got := parseLVMRaid("  lv0 vg0 rwi 5.00 100.00\n")
		if len(got) != 0 {
			t.Fatalf("got %+v, want none (attr shorter than 10 chars)", got)
		}
	})

	t.Run("too few fields skipped", func(t *testing.T) {
		t.Parallel()
		got := parseLVMRaid("  lv0 vg0\n")
		if len(got) != 0 {
			t.Fatalf("got %+v, want none (fewer than 4 fields)", got)
		}
	})

	t.Run("non mirror/raid lvType skipped", func(t *testing.T) {
		t.Parallel()
		got := parseLVMRaid("  lv0 vg0 -wi-ao---- 5.00 100.00\n")
		if len(got) != 0 {
			t.Fatalf("got %+v, want none (lvType neither m nor r)", got)
		}
	})
}

// TestDmNameToVGName guards the dm-name decoding: "--" is a literal dash, the
// first single dash is the VG/LV boundary.
func TestDmNameToVGName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		dmName string
		want   string
	}{
		{"double-dash VG name", "debian--vg-root", "debian-vg"},
		{"simple VG name", "ol-root", "ol"},
		{"no boundary", "novgboundary", ""},
		{"empty input", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := dmNameToVGName(tt.dmName); got != tt.want {
				t.Errorf("dmNameToVGName(%q) = %q, want %q", tt.dmName, got, tt.want)
			}
		})
	}
}

// TestMergeMountedLVs guards the two device-path forms plus the not-mounted and
// read-failure cases.
func TestMergeMountedLVs(t *testing.T) {
	t.Run("mapper form", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/mounts", []byte("/dev/mapper/debian--vg-root / ext4 rw,relatime 0 0\n"))
		})
		vgs := []models.LVMVG{{Name: "debian-vg"}}
		mergeMountedLVs(vgs)
		if !vgs[0].HasMountedLV {
			t.Error("expected HasMountedLV=true via /dev/mapper form")
		}
	})

	t.Run("plain vg/lv form", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/mounts", []byte("/dev/ol/root / xfs rw,relatime 0 0\n"))
		})
		vgs := []models.LVMVG{{Name: "ol"}}
		mergeMountedLVs(vgs)
		if !vgs[0].HasMountedLV {
			t.Error("expected HasMountedLV=true via /dev/<vg>/<lv> form")
		}
	})

	t.Run("VG not mounted stays false", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/mounts", []byte("/dev/mapper/ol-root / xfs rw,relatime 0 0\n"))
		})
		vgs := []models.LVMVG{{Name: "leftover"}}
		mergeMountedLVs(vgs)
		if vgs[0].HasMountedLV {
			t.Error("expected HasMountedLV=false for an unrelated VG")
		}
	})

	t.Run("/proc/mounts read failure no-ops", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		vgs := []models.LVMVG{{Name: "ol"}}
		mergeMountedLVs(vgs)
		if vgs[0].HasMountedLV {
			t.Error("expected HasMountedLV=false when /proc/mounts is unreadable")
		}
	})
}
