package collectors

import (
	"testing"
)

// Real-world `vgs` output: two VGs, one nearly full.
// Format: vg_name, vg_size, vg_free, vg_attr (--nosuffix --units g)
const vgsOutputNormal = `  pve  99.50  10.00  wz--n-
  data 199.00  2.00  wz--n-
`

// VG where free space is essentially zero (triggers CRIT in checkLVM).
const vgsOutputFull = `  myvg  50.00  0.50  wz--n-
`

// Empty output — lvm2 present but no VGs configured.
const vgsOutputEmpty = ``

func TestParseVGs(t *testing.T) {
	t.Run("two VGs parsed correctly", func(t *testing.T) {
		vgs := parseVGs(vgsOutputNormal)
		if len(vgs) != 2 {
			t.Fatalf("len(vgs) = %d, want 2", len(vgs))
		}

		pve := vgs[0]
		if pve.Name != "pve" {
			t.Errorf("Name = %q, want pve", pve.Name)
		}
		if pve.SizeGB != 99.50 {
			t.Errorf("SizeGB = %g, want 99.50", pve.SizeGB)
		}
		if pve.FreeGB != 10.00 {
			t.Errorf("FreeGB = %g, want 10.00", pve.FreeGB)
		}
		wantFreePct := 10.00 / 99.50 * 100
		if abs(pve.FreePct-wantFreePct) > 0.01 {
			t.Errorf("FreePct = %g, want ~%g", pve.FreePct, wantFreePct)
		}

		data := vgs[1]
		if data.Name != "data" {
			t.Errorf("Name = %q, want data", data.Name)
		}
	})

	t.Run("empty output returns nil slice", func(t *testing.T) {
		vgs := parseVGs(vgsOutputEmpty)
		if len(vgs) != 0 {
			t.Errorf("len(vgs) = %d, want 0", len(vgs))
		}
	})

	t.Run("single nearly-full VG", func(t *testing.T) {
		vgs := parseVGs(vgsOutputFull)
		if len(vgs) != 1 {
			t.Fatalf("len(vgs) = %d, want 1", len(vgs))
		}
		// 0.50 free of 50.00 = 1% free = 99% used
		if vgs[0].FreePct < 0.5 || vgs[0].FreePct > 2.0 {
			t.Errorf("FreePct = %g, want ~1.0", vgs[0].FreePct)
		}
	})
}

// Real-world `lvs` output: thin pool + snapshot + regular LV.
// Columns: lv_name, vg_name, lv_attr, data_percent, metadata_percent, origin, lv_size
const lvsOutputMixed = `  data   pve  twi-aotz-- 65.00  1.20   8.00
  snap0  pve  swi-a-s---  78.00  0.00 vm-100-disk-0 2.00
  vm-100-disk-0 pve  Vwi-aotz-- 0.00 0.00   8.00
`

// Thin snapshot of a thin LV — lv_attr[0]='V', attr[8]='k' (real Legion format).
// Output: snap_thin dsd_test Vwi---tz-k 0 0 thin_vol 30.00
const lvsOutputThinSnapshot = `  snap_thin dsd_test Vwi---tz-k 0.00 0.00 thin_vol 30.00
`

// Thin pool at critical data usage.
const lvsOutputThinCrit = `  data pve  twi-aotz-- 91.00  2.50   100.00
`

// Snapshot near overflow.
const lvsOutputSnapOverflow = `  snap1 pve  swi-a-s---  95.00  0.00 vm-200-disk-0 2.00
`

// Real-world classic (CoW) snapshot: metadata_percent is BLANK — only thin/cache
// pools report it. The blank column collapses under strings.Fields, so a naive
// fixed-index read of origin would pick up lv_size instead. Regression fixture.
const lvsOutputClassicSnapBlankMeta = `  snap0  pve  swi-a-s---  78.00         vm-100-disk-0  2.00
`

// No thin pools or snapshots — regular LVs only.
const lvsOutputNoSpecial = `  root  ol  -wi-ao---- 0.00 0.00   30.00
  swap  ol  -wi-ao---- 0.00 0.00    4.00
`

func TestParseLVs(t *testing.T) {
	t.Run("thin pool and snapshot parsed", func(t *testing.T) {
		pools, snaps := parseLVs(lvsOutputMixed)

		if len(pools) != 1 {
			t.Fatalf("thin pools = %d, want 1", len(pools))
		}
		p := pools[0]
		if p.Name != "data" {
			t.Errorf("pool name = %q, want data", p.Name)
		}
		if p.VG != "pve" {
			t.Errorf("pool VG = %q, want pve", p.VG)
		}
		if p.DataPct != 65.00 {
			t.Errorf("DataPct = %g, want 65.00", p.DataPct)
		}
		if p.MetaPct != 1.20 {
			t.Errorf("MetaPct = %g, want 1.20", p.MetaPct)
		}
		if p.SizeGB != 8.00 {
			t.Errorf("SizeGB = %g, want 8.00", p.SizeGB)
		}

		if len(snaps) != 1 {
			t.Fatalf("snapshots = %d, want 1", len(snaps))
		}
		s := snaps[0]
		if s.Name != "snap0" {
			t.Errorf("snapshot name = %q, want snap0", s.Name)
		}
		if s.Origin != "vm-100-disk-0" {
			t.Errorf("origin = %q, want vm-100-disk-0", s.Origin)
		}
		if s.DataPct != 78.00 {
			t.Errorf("snapshot DataPct = %g, want 78.00", s.DataPct)
		}
	})

	t.Run("classic snapshot with blank metadata_percent keeps correct origin", func(t *testing.T) {
		_, snaps := parseLVs(lvsOutputClassicSnapBlankMeta)
		if len(snaps) != 1 {
			t.Fatalf("snapshots = %d, want 1", len(snaps))
		}
		if snaps[0].Origin != "vm-100-disk-0" {
			t.Errorf("origin = %q, want vm-100-disk-0 (blank meta%% must not shift origin to lv_size)", snaps[0].Origin)
		}
		if snaps[0].DataPct != 78.00 {
			t.Errorf("DataPct = %g, want 78.00", snaps[0].DataPct)
		}
	})

	t.Run("no thin pools or snapshots", func(t *testing.T) {
		pools, snaps := parseLVs(lvsOutputNoSpecial)
		if len(pools) != 0 {
			t.Errorf("thin pools = %d, want 0", len(pools))
		}
		if len(snaps) != 0 {
			t.Errorf("snapshots = %d, want 0", len(snaps))
		}
	})

	t.Run("critical thin pool data usage", func(t *testing.T) {
		pools, _ := parseLVs(lvsOutputThinCrit)
		if len(pools) != 1 {
			t.Fatalf("thin pools = %d, want 1", len(pools))
		}
		if pools[0].DataPct != 91.00 {
			t.Errorf("DataPct = %g, want 91.00", pools[0].DataPct)
		}
		if pools[0].SizeGB != 100.00 {
			t.Errorf("SizeGB = %g, want 100.00", pools[0].SizeGB)
		}
	})

	t.Run("snapshot near overflow", func(t *testing.T) {
		_, snaps := parseLVs(lvsOutputSnapOverflow)
		if len(snaps) != 1 {
			t.Fatalf("snapshots = %d, want 1", len(snaps))
		}
		if snaps[0].DataPct != 95.00 {
			t.Errorf("snapshot DataPct = %g, want 95.00", snaps[0].DataPct)
		}
	})

	t.Run("empty output returns no data", func(t *testing.T) {
		pools, snaps := parseLVs("")
		if len(pools) != 0 || len(snaps) != 0 {
			t.Errorf("expected empty slices, got pools=%d snaps=%d", len(pools), len(snaps))
		}
	})

	t.Run("thin snapshot (Vwi---tz-k) parsed as snapshot", func(t *testing.T) {
		// Real Legion format: snap_thin is a thin LV snapshot of thin_vol.
		// lv_attr[0]='V' (thin volume), lv_attr[8]='k' (snapshot marker).
		_, snaps := parseLVs(lvsOutputThinSnapshot)
		if len(snaps) != 1 {
			t.Fatalf("snapshots = %d, want 1 (thin snapshot not detected)", len(snaps))
		}
		if snaps[0].Name != "snap_thin" {
			t.Errorf("Name = %q, want snap_thin", snaps[0].Name)
		}
		if snaps[0].Origin != "thin_vol" {
			t.Errorf("Origin = %q, want thin_vol", snaps[0].Origin)
		}
	})
}

// pv_attr field format: [allocatable][exported][missing]
//
//	a--  = active, not exported, not missing (healthy)
//	a-m  = active, not exported, MISSING  ← attr[2]=='m'
//
// Real `pvs --noheadings -o vg_name,pv_attr` output — no device path column.
const pvsOutputWithMissing = `  pve  a--
  pve  a-m
  data  a--
`

const pvsOutputAllHealthy = `  myvg  a--
  myvg  a--
`

func TestMergeMissingPVs(t *testing.T) {
	t.Run("one missing PV counted", func(t *testing.T) {
		vgs := parseVGs(vgsOutputNormal) // pve + data
		mergeMissingPVs(pvsOutputWithMissing, vgs)

		var pve, data *struct{ MissingPVs int }
		for i := range vgs {
			switch vgs[i].Name {
			case "pve":
				pve = &struct{ MissingPVs int }{vgs[i].MissingPVs}
			case "data":
				data = &struct{ MissingPVs int }{vgs[i].MissingPVs}
			}
		}
		if pve == nil {
			t.Fatal("pve VG not found")
		}
		if pve.MissingPVs != 1 {
			t.Errorf("pve.MissingPVs = %d, want 1", pve.MissingPVs)
		}
		if data == nil {
			t.Fatal("data VG not found")
		}
		if data.MissingPVs != 0 {
			t.Errorf("data.MissingPVs = %d, want 0", data.MissingPVs)
		}
	})

	t.Run("no missing PVs — counts stay zero", func(t *testing.T) {
		vgs := parseVGs(vgsOutputFull) // single myvg
		mergeMissingPVs(pvsOutputAllHealthy, vgs)
		if vgs[0].MissingPVs != 0 {
			t.Errorf("MissingPVs = %d, want 0", vgs[0].MissingPVs)
		}
	})
}

// abs returns the absolute value of a float64.
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
