//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestHWRaidCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewHWRaidCollector()
	if c.Name() != "HardwareRAID" {
		t.Errorf("Name() = %q, want HardwareRAID", c.Name())
	}
	if c.Timeout() <= 0 {
		t.Errorf("Timeout() = %v, want > 0", c.Timeout())
	}
}

// TestHWRaidCollector_Collect_NoToolInstalled guards the gate: none of the
// vendor CLIs are on $PATH -> Collect returns an empty (not nil, not
// Available) *models.HWRaidInfo without invoking any command.
func TestHWRaidCollector_Collect_NoToolInstalled(t *testing.T) {
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		// No lookpath/<tool> Cached entries seeded -> hasCmd() is false for all.
	})
	c := NewHWRaidCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.HWRaidInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.HWRaidInfo", raw)
	}
	if info.Available {
		t.Error("Available = true, want false (no tool installed)")
	}
	if info.Tool != "" {
		t.Errorf("Tool = %q, want empty", info.Tool)
	}
}

// TestHWRaidCollector_Collect_StorcliHealthy exercises the storcli branch end
// to end: tool present, command succeeds, JSON parses into one healthy
// controller.
func TestHWRaidCollector_Collect_StorcliHealthy(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/storcli64": []byte("/opt/MegaRAID/storcli/storcli64"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("storcli64", []string{"/cALL", "show", "all", "J"}, storcliHealthyJSON, 0)
	})
	c := NewHWRaidCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HWRaidInfo)
	if !info.Available {
		t.Error("Available = false, want true")
	}
	if info.Tool != "storcli" {
		t.Errorf("Tool = %q, want storcli (64/cli suffix stripped)", info.Tool)
	}
	if len(info.Controllers) != 1 {
		t.Fatalf("Controllers = %+v, want exactly 1", info.Controllers)
	}
	if info.NeedsRoot || info.ReadFailed {
		t.Errorf("NeedsRoot/ReadFailed = %v/%v, want false/false", info.NeedsRoot, info.ReadFailed)
	}
}

// TestHWRaidCollector_Collect_SsacliDegraded exercises the ssacli (HPE)
// text-parsing branch end to end.
func TestHWRaidCollector_Collect_SsacliDegraded(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/ssacli": []byte("/usr/sbin/ssacli"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("ssacli", []string{"ctrl", "all", "show", "config"}, ssacliDegradedText, 0)
	})
	c := NewHWRaidCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HWRaidInfo)
	if !info.Available {
		t.Error("Available = false, want true")
	}
	if info.Tool != "ssacli" {
		t.Errorf("Tool = %q, want ssacli", info.Tool)
	}
	if len(info.Controllers) != 1 {
		t.Fatalf("Controllers = %+v, want exactly 1", info.Controllers)
	}
}

// TestHWRaidCollector_Collect_CommandFails_NonRoot guards the "CLI present
// but the command failed" + non-root branch: degrade to NeedsRoot, never a
// silent healthy verdict. Forced deterministically via the geteuid seam.
func TestHWRaidCollector_Collect_CommandFails_NonRoot(t *testing.T) {
	swapGeteuid(t, 1000)
	withCombinedFixture(t, map[string][]byte{
		"lookpath/storcli64": []byte("/opt/MegaRAID/storcli/storcli64"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("storcli64", []string{"/cALL", "show", "all", "J"}, "", 1)
	})
	c := NewHWRaidCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HWRaidInfo)
	if !info.Available {
		t.Error("Available = false, want true (command failed, but tool IS installed)")
	}
	if !info.NeedsRoot {
		t.Errorf("info = %+v, want NeedsRoot=true for a non-root command failure", info)
	}
	if len(info.Controllers) != 0 {
		t.Errorf("Controllers = %+v, want empty on a failed read", info.Controllers)
	}
}

// TestHWRaidCollector_Collect_CommandFails_Root guards the same branch when
// running as root: a root failure is a genuine ReadFailed, never mis-
// classified as NeedsRoot (sudo cannot fix an already-root failure). Forced
// deterministically via the geteuid seam (real test binaries aren't root, so
// this branch was previously unreachable in CI without the seam).
func TestHWRaidCollector_Collect_CommandFails_Root(t *testing.T) {
	swapGeteuid(t, 0)
	withCombinedFixture(t, map[string][]byte{
		"lookpath/storcli64": []byte("/opt/MegaRAID/storcli/storcli64"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("storcli64", []string{"/cALL", "show", "all", "J"}, "", 1)
	})
	c := NewHWRaidCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HWRaidInfo)
	if !info.Available {
		t.Error("Available = false, want true (command failed, but tool IS installed)")
	}
	if info.NeedsRoot {
		t.Error("NeedsRoot = true, want false — a root run's failure is a genuine error, not a privilege gap")
	}
	if !info.ReadFailed {
		t.Errorf("info = %+v, want ReadFailed=true for a root command failure", info)
	}
	if len(info.Controllers) != 0 {
		t.Errorf("Controllers = %+v, want empty on a failed read", info.Controllers)
	}
}

// TestHWRaidCollector_Collect_StorcliUnparseableOutput guards the "command
// succeeded but the JSON shape is wrong" branch — a read failure, not a
// silent "no controller found".
func TestHWRaidCollector_Collect_StorcliUnparseableOutput(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/storcli64": []byte("/opt/MegaRAID/storcli/storcli64"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("storcli64", []string{"/cALL", "show", "all", "J"}, "not json at all", 0)
	})
	c := NewHWRaidCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HWRaidInfo)
	if !info.Available || !info.ReadFailed {
		t.Errorf("Available/ReadFailed = %v/%v, want true/true", info.Available, info.ReadFailed)
	}
}

// TestHWRaidCollector_Collect_ToolInstalledNoControllers guards the "CLI
// present, box has no card" gate: a well-formed JSON response listing zero
// controllers must gate off to nil, not a phantom "RAID OK" row.
func TestHWRaidCollector_Collect_ToolInstalledNoControllers(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/storcli64": []byte("/opt/MegaRAID/storcli/storcli64"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("storcli64", []string{"/cALL", "show", "all", "J"}, `{"Controllers":[]}`, 0)
	})
	c := NewHWRaidCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("Collect() = %v, want nil (no controllers responded)", raw)
	}
}

// TestHWRaidCollector_Collect_SchemaDriftedControllersReadFailed is the
// regression test for internal-collectors-16-03: the JSON DID list a
// controller entry (rawCount > 0) but it had no recognizable Success/VD/PD
// data — a schema-drifted response, not "genuinely no controller card"
// (which is the rawCount==0 case covered by
// TestHWRaidCollector_Collect_ToolInstalledNoControllers). Must set
// ReadFailed, not silently return nil.
func TestHWRaidCollector_Collect_SchemaDriftedControllersReadFailed(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/storcli64": []byte("/opt/MegaRAID/storcli/storcli64"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("storcli64", []string{"/cALL", "show", "all", "J"},
			`{"Controllers":[{"Command Status":{"Status":"Failure"},"Response Data":{}}]}`, 0)
	})
	c := NewHWRaidCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.HWRaidInfo)
	if !ok || info == nil {
		t.Fatalf("Collect() = %v, want a non-nil *models.HWRaidInfo (schema-drifted response must not gate off silently)", raw)
	}
	if !info.ReadFailed {
		t.Error("ReadFailed = false, want true when every controller entry had no recognizable data")
	}
}

func TestIsHWRaidPresent(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/ssacli": []byte("/usr/sbin/ssacli"),
		}, nil, nil)
		if !IsHWRaidPresent() {
			t.Error("IsHWRaidPresent() = false, want true")
		}
	})
	t.Run("absent", func(t *testing.T) {
		withCombinedFixture(t, nil, nil, nil)
		if IsHWRaidPresent() {
			t.Error("IsHWRaidPresent() = true, want false")
		}
	})
}

// TestHwRaidTool_PreferenceOrder guards that hwRaidTool() picks the
// most-preferred CLI (storcli64) when multiple are present on $PATH.
func TestHwRaidTool_PreferenceOrder(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/storcli64": []byte("/opt/MegaRAID/storcli/storcli64"),
		"lookpath/ssacli":    []byte("/usr/sbin/ssacli"),
	}, nil, nil)
	if got := hwRaidTool(); got != "storcli64" {
		t.Errorf("hwRaidTool() = %q, want storcli64 (most preferred)", got)
	}
}

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
	ctrls, _, ok := parseStorcli(storcliDegradedJSON)
	if !ok {
		t.Fatal("well-formed JSON must parse ok=true")
	}
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
	ctrls, _, ok := parseStorcli(storcliHealthyJSON)
	if !ok {
		t.Fatal("well-formed JSON must parse ok=true")
	}
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

// TestNormalizeStorcliVD_AllStates guards every abbreviated storcli VD state
// (Optl/Dgrd/Pdgd/OfLn/Rec) plus the unknown-state passthrough default.
func TestNormalizeStorcliVD_AllStates(t *testing.T) {
	cases := []struct {
		name           string
		state          string
		wantState      string
		wantDegraded   bool
		wantOffline    bool
		wantRebuilding bool
	}{
		{"optimal abbrev", "Optl", "Optimal", false, false, false},
		{"optimal full word", "optimal", "Optimal", false, false, false},
		{"degraded abbrev", "Dgrd", "Degraded", true, false, false},
		{"degraded full word", "degraded", "Degraded", true, false, false},
		{"partially degraded abbrev", "Pdgd", "Partially Degraded", true, false, false},
		{"partially degraded full word", "partially degraded", "Partially Degraded", true, false, false},
		{"offline abbrev", "OfLn", "Offline", false, true, false},
		{"offline full word", "offline", "Offline", false, true, false},
		{"recovery abbrev", "Rec", "Rebuilding", false, false, true},
		{"rebuild full word", "rebuilding", "Rebuilding", false, false, true},
		{"unknown state passthrough", "SomeNewState", "SomeNewState", false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vd := normalizeStorcliVD("test", storcliVD{State: c.state})
			if vd.State != c.wantState {
				t.Errorf("State = %q, want %q", vd.State, c.wantState)
			}
			if vd.Degraded != c.wantDegraded || vd.Offline != c.wantOffline || vd.Rebuilding != c.wantRebuilding {
				t.Errorf("flags = degraded=%v offline=%v rebuilding=%v, want %v/%v/%v",
					vd.Degraded, vd.Offline, vd.Rebuilding, c.wantDegraded, c.wantOffline, c.wantRebuilding)
			}
		})
	}
}

// TestNormalizeStorcliPD_AllStates guards every abbreviated storcli PD state.
func TestNormalizeStorcliPD_AllStates(t *testing.T) {
	cases := []struct {
		name           string
		state          string
		wantState      string
		wantFailed     bool
		wantRebuilding bool
	}{
		{"online abbrev", "Onln", "Online", false, false},
		{"online full word", "online", "Online", false, false},
		{"rebuild abbrev", "Rbld", "Rebuilding", false, true},
		{"rebuild full word", "rebuilding", "Rebuilding", false, true},
		{"failed literal", "Failed", "Failed", true, false},
		{"unconfigured bad", "UBad", "Failed", true, false},
		{"offline abbrev", "Offln", "Offline", true, false},
		{"unknown state passthrough", "SomeNewState", "SomeNewState", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pd := normalizeStorcliPD(storcliPD{State: c.state})
			if pd.State != c.wantState {
				t.Errorf("State = %q, want %q", pd.State, c.wantState)
			}
			if pd.Failed != c.wantFailed || pd.Rebuilding != c.wantRebuilding {
				t.Errorf("flags = failed=%v rebuilding=%v, want %v/%v", pd.Failed, pd.Rebuilding, c.wantFailed, c.wantRebuilding)
			}
		})
	}
}

// TestStorcliBBU_CachevaultFallback guards the fallback to Cachevault_Info
// when BBU_Info is absent, and the "neither present" empty case.
func TestStorcliBBU_CachevaultFallback(t *testing.T) {
	t.Run("BBU present takes priority", func(t *testing.T) {
		state, degraded, _ := storcliBBU([]struct {
			State string `json:"State"`
		}{{State: "Degraded"}}, []struct {
			State string `json:"State"`
		}{{State: "Optimal"}})
		if state != "Degraded" || !degraded {
			t.Errorf("state=%q degraded=%v, want Degraded/true", state, degraded)
		}
	})
	t.Run("Cachevault fallback when no BBU", func(t *testing.T) {
		state, degraded, _ := storcliBBU(nil, []struct {
			State string `json:"State"`
		}{{State: "Optimal"}})
		if state != "Optimal" || degraded {
			t.Errorf("state=%q degraded=%v, want Optimal/false", state, degraded)
		}
	})
	t.Run("neither present", func(t *testing.T) {
		state, degraded, unreadable := storcliBBU(nil, nil)
		if state != "" || degraded || unreadable {
			t.Errorf("state=%q degraded=%v unreadable=%v, want empty/false/false", state, degraded, unreadable)
		}
	})
}

// TestStorcliBBU_PresentButStateUnreadable is the regression test for
// internal-collectors-16-02: a BBU entry present in the JSON but with an
// empty State field (schema drift — a renamed key) must be distinguished
// from no BBU/CacheVault entry at all.
func TestStorcliBBU_PresentButStateUnreadable(t *testing.T) {
	t.Parallel()
	state, degraded, unreadable := storcliBBU([]struct {
		State string `json:"State"`
	}{{State: ""}}, nil)
	if state != "" || degraded {
		t.Errorf("state=%q degraded=%v, want empty/false", state, degraded)
	}
	if !unreadable {
		t.Error("unreadable = false, want true when a BBU entry is present but its State is empty")
	}
}

// TestSsacliModel_NoSlotMarker guards the fallback when a line has no
// " in Slot " marker at all (ssacliModel returns "").
func TestSsacliModel_NoSlotMarker(t *testing.T) {
	if got := ssacliModel("not a controller line"); got != "" {
		t.Errorf("ssacliModel() = %q, want empty", got)
	}
}

// TestSlotNumber_FallbackOnUnparseable guards the fallback value when the
// text after " in Slot " has no digits to parse.
func TestSlotNumber_FallbackOnUnparseable(t *testing.T) {
	if got := slotNumber("Smart Array P440ar in Slot Embedded", 7); got != 7 {
		t.Errorf("slotNumber() = %d, want fallback 7", got)
	}
}

// TestSsacliParen_NoParens guards the empty-string return when a line has no
// parenthesized segment at all.
func TestSsacliParen_NoParens(t *testing.T) {
	if got := ssacliParen("logicaldrive 1 no parens here"); got != "" {
		t.Errorf("ssacliParen() = %q, want empty", got)
	}
}

// TestApplySsacliVDStatus_AllBranches guards every ssacli VD status string
// class: OK, interim-recovery/degraded, recover/rebuild/expand, fail, and an
// unrecognized status left verbatim.
func TestApplySsacliVDStatus_AllBranches(t *testing.T) {
	cases := []struct {
		name           string
		status         string
		wantState      string
		wantDegraded   bool
		wantRebuilding bool
		wantOffline    bool
	}{
		{"ok", "OK", "Optimal", false, false, false},
		{"interim recovery mode", "Interim Recovery Mode", "Degraded", true, false, false},
		{"degraded literal", "degraded", "Degraded", true, false, false},
		{"recovering", "Recovering", "Rebuilding", false, true, false},
		{"rebuild", "Rebuild", "Rebuilding", false, true, false},
		{"expanding", "Expanding", "Rebuilding", false, true, false},
		{"failed", "Failed", "Offline", false, false, true},
		{"unknown status", "Weird Status", "Weird Status", false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var vd models.HWRaidVD
			applySsacliVDStatus(&vd, c.status)
			if vd.State != c.wantState {
				t.Errorf("State = %q, want %q", vd.State, c.wantState)
			}
			if vd.Degraded != c.wantDegraded || vd.Rebuilding != c.wantRebuilding || vd.Offline != c.wantOffline {
				t.Errorf("flags = degraded=%v rebuilding=%v offline=%v, want %v/%v/%v",
					vd.Degraded, vd.Rebuilding, vd.Offline, c.wantDegraded, c.wantRebuilding, c.wantOffline)
			}
		})
	}
}

// TestApplySsacliPDStatus_AllBranches guards every ssacli PD status string
// class: OK, predictive failure, rebuild, fail, and unrecognized passthrough.
func TestApplySsacliPDStatus_AllBranches(t *testing.T) {
	cases := []struct {
		name           string
		status         string
		wantState      string
		wantPredictive bool
		wantRebuilding bool
		wantFailed     bool
	}{
		{"ok", "OK", "Online", false, false, false},
		{"predictive failure", "Predictive Failure", "Predictive Failure", true, false, false},
		{"rebuilding", "Rebuilding", "Rebuilding", false, true, false},
		{"failed", "Failed", "Failed", false, false, true},
		{"unknown status", "Weird Status", "Weird Status", false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var pd models.HWRaidPD
			applySsacliPDStatus(&pd, c.status)
			if pd.State != c.wantState {
				t.Errorf("State = %q, want %q", pd.State, c.wantState)
			}
			if pd.Predictive != c.wantPredictive || pd.Rebuilding != c.wantRebuilding || pd.Failed != c.wantFailed {
				t.Errorf("flags = predictive=%v rebuilding=%v failed=%v, want %v/%v/%v",
					pd.Predictive, pd.Rebuilding, pd.Failed, c.wantPredictive, c.wantRebuilding, c.wantFailed)
			}
		})
	}
}

func TestParseStorcliGarbageIsEmpty(t *testing.T) {
	ctrls, _, ok := parseStorcli("not json at all")
	if ctrls != nil {
		t.Errorf("garbage must parse to nil controllers, got %+v", ctrls)
	}
	if ok {
		t.Error("garbage must report ok=false so Collect() takes the ReadFailed path, not the silent gate-off path")
	}
}

// TestParseStorcliUnresponsiveControllerSkipped guards the "no card at that
// index" branch: a controller entry with a non-Success command status and no
// VD/PD data must be dropped entirely, not surfaced as an empty/zero-value
// controller.
func TestParseStorcliUnresponsiveControllerSkipped(t *testing.T) {
	const unresponsive = `{
"Controllers":[
  {
    "Command Status":{"Controller":0,"Status":"Failure","Description":"Controller not found"},
    "Response Data":{}
  },
  {
    "Command Status":{"Controller":1,"Status":"Success"},
    "Response Data":{
      "Product Name":"MegaRAID 9560-8i",
      "VD LIST":[{"DG/VD":"0/0","TYPE":"RAID1","State":"Optl","Name":"data"}]
    }
  }
]
}`
	ctrls, _, ok := parseStorcli(unresponsive)
	if !ok {
		t.Fatal("well-formed JSON must parse ok=true")
	}
	if len(ctrls) != 1 {
		t.Fatalf("controllers = %d, want 1 (unresponsive controller 0 must be dropped)", len(ctrls))
	}
	if ctrls[0].ID != 1 {
		t.Errorf("surviving controller ID = %d, want 1", ctrls[0].ID)
	}
}
