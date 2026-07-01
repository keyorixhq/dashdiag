//go:build linux

package collectors

import "testing"

// Real-shape output of `storcli /cALL show all J` on an LSI/Broadcom MegaRAID / Dell
// PERC controller. Controller 0 has a healthy RAID1 (OS) and a DEGRADED RAID5 (DATA)
// with one Failed member and one Rebuilding member. BBU is Optimal.
const storcliDegradedJSON = `{
"Controllers":[
  {
    "Command Status":{
      "CLI Version":"007.1704.0000.0000",
      "Controller":0,
      "Status":"Success",
      "Description":"None"
    },
    "Response Data":{
      "Product Name":"PERC H730P Mini",
      "VD LIST":[
        {"DG/VD":"0/0","TYPE":"RAID1","State":"Optl","Access":"RW","Name":"OS"},
        {"DG/VD":"1/1","TYPE":"RAID5","State":"Dgrd","Access":"RW","Name":"DATA"}
      ],
      "PD LIST":[
        {"EID:Slt":"32:0","DID":0,"State":"Onln","DG":0,"Med":"SSD"},
        {"EID:Slt":"32:3","DID":3,"State":"Failed","DG":1,"Med":"HDD"},
        {"EID:Slt":"32:4","DID":4,"State":"Rbld","DG":1,"Med":"HDD"}
      ],
      "BBU_Info":[{"Model":"BBU","State":"Optimal"}]
    }
  }
]
}`

// A fully healthy controller — every VD Optimal, every PD Online, BBU Optimal.
const storcliHealthyJSON = `{
"Controllers":[
  {
    "Command Status":{"Controller":0,"Status":"Success"},
    "Response Data":{
      "Product Name":"MegaRAID 9560-8i",
      "VD LIST":[{"DG/VD":"0/0","TYPE":"RAID10","State":"Optl","Name":"data"}],
      "PD LIST":[
        {"EID:Slt":"252:0","State":"Onln"},
        {"EID:Slt":"252:1","State":"Onln"}
      ],
      "Cachevault_Info":[{"State":"Optimal"}]
    }
  }
]
}`

func TestParseStorcliDegraded(t *testing.T) {
	ctrls := parseStorcli(storcliDegradedJSON)
	if len(ctrls) != 1 {
		t.Fatalf("controllers = %d, want 1", len(ctrls))
	}
	c := ctrls[0]
	if c.ID != 0 || c.Model != "PERC H730P Mini" {
		t.Errorf("controller id/model = %d/%q", c.ID, c.Model)
	}
	if len(c.VirtualDrives) != 2 {
		t.Fatalf("VDs = %d, want 2", len(c.VirtualDrives))
	}
	if c.VirtualDrives[0].Degraded {
		t.Error("VD0 (OS, Optl) must NOT be degraded")
	}
	if !c.VirtualDrives[1].Degraded || c.VirtualDrives[1].State != "Degraded" {
		t.Errorf("VD1 (DATA, Dgrd) must be Degraded, got %+v", c.VirtualDrives[1])
	}
	var failed, rebuilding int
	for _, pd := range c.PhysicalDrives {
		if pd.Failed {
			failed++
		}
		if pd.Rebuilding {
			rebuilding++
		}
	}
	if failed != 1 || rebuilding != 1 {
		t.Errorf("failed=%d rebuilding=%d, want 1/1", failed, rebuilding)
	}
	if c.BBUDegraded {
		t.Error("BBU Optimal must not be degraded")
	}
}

func TestParseStorcliHealthy(t *testing.T) {
	ctrls := parseStorcli(storcliHealthyJSON)
	if len(ctrls) != 1 {
		t.Fatalf("controllers = %d, want 1", len(ctrls))
	}
	c := ctrls[0]
	for _, vd := range c.VirtualDrives {
		if vd.Degraded || vd.Offline || vd.Rebuilding {
			t.Errorf("healthy VD flagged: %+v", vd)
		}
	}
	for _, pd := range c.PhysicalDrives {
		if pd.Failed || pd.Rebuilding || pd.Predictive {
			t.Errorf("healthy PD flagged: %+v", pd)
		}
	}
	if c.BBUDegraded {
		t.Error("CacheVault Optimal must not be degraded")
	}
}

// `ssacli ctrl all show config` on an HPE Smart Array: a healthy RAID1 array and a
// RAID5 array in "Interim Recovery Mode" (degraded) with a Failed and a Rebuilding disk.
const ssacliDegradedText = `
Smart Array P440ar in Slot 0 (Embedded)

   Array A (Solid State SATA, Unused Space: 0 MB)

      logicaldrive 1 (1.6 TB, RAID 1, OK)

      physicaldrive 1I:1:1 (port 1I:box 1:bay 1, Solid State SATA, 1.6 TB, OK)
      physicaldrive 1I:1:2 (port 1I:box 1:bay 2, Solid State SATA, 1.6 TB, OK)

   Array B (SAS HDD, Unused Space: 0 MB)

      logicaldrive 2 (5.5 TB, RAID 5, Interim Recovery Mode)

      physicaldrive 2I:1:5 (port 2I:box 1:bay 5, SAS HDD, 1.8 TB, OK)
      physicaldrive 2I:1:6 (port 2I:box 1:bay 6, SAS HDD, 1.8 TB, Failed)
      physicaldrive 2I:1:7 (port 2I:box 1:bay 7, SAS HDD, 1.8 TB, Rebuilding)
`

func TestParseSsacliDegraded(t *testing.T) {
	ctrls := parseSsacli(ssacliDegradedText)
	if len(ctrls) != 1 {
		t.Fatalf("controllers = %d, want 1", len(ctrls))
	}
	c := ctrls[0]
	if c.Model != "Smart Array P440ar" {
		t.Errorf("model = %q, want Smart Array P440ar", c.Model)
	}
	if len(c.VirtualDrives) != 2 {
		t.Fatalf("VDs = %d, want 2", len(c.VirtualDrives))
	}
	if c.VirtualDrives[0].Degraded {
		t.Error("logicaldrive 1 (OK) must not be degraded")
	}
	if !c.VirtualDrives[1].Degraded {
		t.Errorf("logicaldrive 2 (Interim Recovery Mode) must be degraded, got %+v", c.VirtualDrives[1])
	}
	var failed, rebuilding, ok int
	for _, pd := range c.PhysicalDrives {
		switch {
		case pd.Failed:
			failed++
		case pd.Rebuilding:
			rebuilding++
		case pd.State == "Online":
			ok++
		}
	}
	if failed != 1 || rebuilding != 1 || ok != 3 {
		t.Errorf("pd states failed=%d rebuilding=%d online=%d, want 1/1/3", failed, rebuilding, ok)
	}
	if c.PhysicalDrives[3].Location != "2I:1:6" {
		t.Errorf("failed PD location = %q, want 2I:1:6", c.PhysicalDrives[3].Location)
	}
}

func TestParseStorcliGarbageIsEmpty(t *testing.T) {
	if ctrls := parseStorcli("not json at all"); ctrls != nil {
		t.Errorf("garbage must parse to nil (ReadFailed path handles it), got %+v", ctrls)
	}
}
