//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	hwrFldState    = "State"
	hwrStatRebuilt = "Rebuilding"
	hwrKwRebuild   = "rebuild"
	hwrStatOptimal = "Optimal"
	hwrPfxSlot     = " in Slot "
	hwrStatOffline = "Offline"
	hwrStatFailed  = "Failed"
	hwrKwFail      = "fail"
)

// HWRaidCollector reads hardware-RAID controller health via the vendor CLI:
// storcli/perccli (LSI/Broadcom MegaRAID + Dell PERC — identical output) and
// ssacli/hpssacli (HPE Smart Array). Built against the vendors' documented output
// formats; see hwraid_linux_test.go for the fixtures. NOTE: not yet validated against
// a live controller — same posture as the VMware collector at first ship.
type HWRaidCollector struct{}

func NewHWRaidCollector() *HWRaidCollector        { return &HWRaidCollector{} }
func (c *HWRaidCollector) Name() string           { return "HardwareRAID" }
func (c *HWRaidCollector) Timeout() time.Duration { return 8 * time.Second }

// hwRaidTools are the controller CLIs we know how to read, most-preferred first.
// storcli/perccli emit JSON (robust); ssacli emits structured text.
var hwRaidTools = []string{"storcli64", "storcli", "perccli64", "perccli", "ssacli", "hpssacli"}

// hwRaidTool returns the first controller CLI present, or "".
func hwRaidTool() string {
	for _, t := range hwRaidTools {
		if hasCmd(t) {
			return t
		}
	}
	return ""
}

// IsHWRaidPresent gates registration: a controller CLI is installed. The binary being
// present is the signal a hardware RAID controller is likely in this box — these CLIs
// are vendor-specific and not pulled in as generic dependencies.
func IsHWRaidPresent() bool { return hwRaidTool() != "" }

func (c *HWRaidCollector) Collect(ctx context.Context) (interface{}, error) {
	tool := hwRaidTool()
	if tool == "" {
		return &models.HWRaidInfo{}, nil
	}
	info := &models.HWRaidInfo{Tool: strings.TrimSuffix(strings.TrimSuffix(tool, "64"), "cli") + "cli"}

	var out string
	var err error
	family := strings.HasPrefix(tool, "ssacli") || strings.HasPrefix(tool, "hpssacli")
	if family {
		out, err = runCmdOutput(ctx, tool, "ctrl", "all", "show", "config")
	} else {
		// storcli / perccli: "/cALL show all J" — every controller, JSON output.
		out, err = runCmdOutput(ctx, tool, "/cALL", "show", "all", "J")
	}

	if err != nil {
		// These CLIs read the controller device, which is root-only. A non-root run
		// gets permission-denied — degrade honestly to "could not read", NOT healthy.
		if geteuid() != 0 {
			info.Available, info.NeedsRoot = true, true
			return info, nil
		}
		info.Available, info.ReadFailed = true, true
		return info, nil
	}

	rawCount := -1 // -1 (ssacli family) means "not applicable", never compared below
	if family {
		info.Controllers = parseSsacli(out)
	} else {
		ctrls, n, ok := parseStorcli(out)
		if !ok {
			// The command ran and returned data, but it wasn't the JSON shape we
			// expect (truncated output, unexpected storcli/perccli version schema).
			// That's a read failure, not "no controller" — say so, don't go silent.
			info.Available, info.ReadFailed = true, true
			return info, nil
		}
		info.Controllers = ctrls
		rawCount = n
	}

	// Tool installed but no controller responded (e.g. "No Controller found", or the
	// box has the CLI but no card). Gate off — nothing to report.
	if len(info.Controllers) == 0 {
		// internal-collectors-16-03: rawCount > 0 means the JSON DID list
		// controller entries, just none with data our struct recognized — a
		// schema-drift read failure, not "genuinely no card installed"
		// (which is rawCount == 0, the only case that stays silent).
		if rawCount > 0 {
			info.Available, info.ReadFailed = true, true
			return info, nil
		}
		return nil, nil
	}
	info.Available = true
	return info, nil
}

// ── storcli / perccli (MegaRAID + Dell PERC) — JSON ──────────────────────────

type storcliOutput struct {
	Controllers []struct {
		CommandStatus struct {
			Controller int    `json:"Controller"`
			Status     string `json:"Status"`
		} `json:"Command Status"`
		ResponseData struct {
			ProductName string      `json:"Product Name"`
			VDList      []storcliVD `json:"VD LIST"`
			PDList      []storcliPD `json:"PD LIST"`
			BBUInfo     []struct {
				State string `json:"State"`
			} `json:"BBU_Info"`
			CachevaultInfo []struct {
				State string `json:"State"`
			} `json:"Cachevault_Info"`
		} `json:"Response Data"`
	} `json:"Controllers"`
}

type storcliVD struct {
	DGVD  string `json:"DG/VD"`
	Type  string `json:"TYPE"`
	State string `json:"State"`
	Name  string `json:"Name"`
}

type storcliPD struct {
	EIDSlt string `json:"EID:Slt"`
	State  string `json:"State"`
}

// parseStorcli turns "storcli /cALL show all J" JSON into normalized controllers.
// The second return is false only when the output couldn't be parsed as the
// expected JSON shape at all (truncated/garbled/unrecognized schema) — distinct
// from a well-formed response that legitimately lists zero controllers.
// parseStorcli returns (controllers, rawCount, ok). ok is false only on a
// JSON unmarshal error. rawCount is len(doc.Controllers) BEFORE filtering out
// no-data entries — internal-collectors-16-03: rawCount > 0 but len(ctrls)==0
// means every controller entry existed in the JSON but had no recognizable
// CommandStatus/VDList/PDList data, the signature of a schema-drifted
// response (a renamed JSON key this struct doesn't map), not "no controller
// card installed" (which is rawCount == 0).
func parseStorcli(out string) (ctrls []models.HWRaidController, rawCount int, ok bool) {
	var doc storcliOutput
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, 0, false
	}
	rawCount = len(doc.Controllers)
	for _, c := range doc.Controllers {
		// A controller that failed to respond (no card at that index) carries no data.
		if !strings.EqualFold(c.CommandStatus.Status, "Success") &&
			len(c.ResponseData.VDList) == 0 && len(c.ResponseData.PDList) == 0 {
			continue
		}
		ctrl := models.HWRaidController{ID: c.CommandStatus.Controller, Model: c.ResponseData.ProductName}
		for _, vd := range c.ResponseData.VDList {
			name := vd.Name
			if name == "" {
				name = "VD " + vd.DGVD
			}
			ctrl.VirtualDrives = append(ctrl.VirtualDrives, normalizeStorcliVD(name, vd))
		}
		for _, pd := range c.ResponseData.PDList {
			ctrl.PhysicalDrives = append(ctrl.PhysicalDrives, normalizeStorcliPD(pd))
		}
		ctrl.BBUStatus, ctrl.BBUDegraded, ctrl.BBUStatusUnreadable = storcliBBU(c.ResponseData.BBUInfo, c.ResponseData.CachevaultInfo)
		ctrls = append(ctrls, ctrl)
	}
	return ctrls, rawCount, true
}

// normalizeStorcliVD maps storcli's abbreviated VD states. Optl=Optimal, Dgrd=Degraded,
// Pdgd=Partially Degraded, OfLn=Offline, Rec=Recovery (rebuilding).
func normalizeStorcliVD(name string, vd storcliVD) models.HWRaidVD {
	s := strings.ToLower(strings.TrimSpace(vd.State))
	out := models.HWRaidVD{Name: name, RaidLevel: vd.Type}
	switch {
	case s == "optl" || strings.HasPrefix(s, "optimal"):
		out.State = hwrStatOptimal
	case s == "dgrd" || strings.HasPrefix(s, "degrad"):
		out.State, out.Degraded = "Degraded", true
	case s == "pdgd" || strings.HasPrefix(s, "partially"):
		out.State, out.Degraded = "Partially Degraded", true
	case s == "ofln" || strings.HasPrefix(s, "offl"):
		out.State, out.Offline = hwrStatOffline, true
	case s == "rec" || strings.HasPrefix(s, "recov") || strings.HasPrefix(s, hwrKwRebuild):
		out.State, out.Rebuilding = hwrStatRebuilt, true
	default:
		out.State = vd.State // surface unknown states verbatim rather than assume OK
	}
	return out
}

// normalizeStorcliPD maps storcli's abbreviated PD states. Onln=Online, Offln=Offline,
// Rbld=Rebuild, Failed, UBad=Unconfigured Bad, UGood=Unconfigured Good, GHS/DHS=hotspare.
func normalizeStorcliPD(pd storcliPD) models.HWRaidPD {
	s := strings.ToLower(strings.TrimSpace(pd.State))
	out := models.HWRaidPD{Location: pd.EIDSlt}
	switch {
	case s == "onln" || strings.HasPrefix(s, "onlin"):
		out.State = "Online"
	case s == "rbld" || strings.HasPrefix(s, hwrKwRebuild):
		out.State, out.Rebuilding = hwrStatRebuilt, true
	case s == "failed" || s == "ubad" || strings.HasPrefix(s, hwrKwFail):
		out.State, out.Failed = hwrStatFailed, true
	case s == "offln" || strings.HasPrefix(s, "offl"):
		out.State, out.Failed = hwrStatOffline, true
	default:
		out.State = pd.State
	}
	return out
}

// storcliBBU returns (state, degraded, unreadable). unreadable is true only
// when a BBU/CacheVault entry IS present but its State field came back empty
// (internal-collectors-16-02: a schema-drifted storcli/perccli JSON, or a
// truncated response) — distinct from state=="" because no battery/cachevault
// info array had any entry at all, which is a genuinely healthy "no
// battery-backed cache fitted" case and stays silent.
func storcliBBU(bbu, cv []struct {
	State string `json:"State"`
}) (state string, degraded, unreadable bool) {
	switch {
	case len(bbu) > 0:
		state = bbu[0].State
	case len(cv) > 0:
		state = cv[0].State
	default:
		return "", false, false
	}
	if state == "" {
		return "", false, true
	}
	// hwrStatOptimal is the healthy state for both BBU and CacheVault.
	return state, !strings.EqualFold(strings.TrimSpace(state), hwrStatOptimal), false
}

// ── ssacli / hpssacli (HPE Smart Array) — structured text ─────────────────────

// parseSsacli reads "ssacli ctrl all show config". The compact format lists each
// controller, then its logicaldrive / physicaldrive lines with a trailing status:
//
//	Smart Array P440ar in Slot 0 (Embedded)
//	   Array A (...)
//	      logicaldrive 1 (1.6 TB, RAID 1, OK)
//	      physicaldrive 1I:1:2 (port 1I:box 1:bay 2, SAS HDD, 1.2 TB, Failed)
func parseSsacli(out string) []models.HWRaidController {
	var ctrls []models.HWRaidController
	var cur *models.HWRaidController
	slot := 0
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.Contains(line, hwrPfxSlot):
			if cur != nil {
				ctrls = append(ctrls, *cur)
			}
			slot++
			cur = &models.HWRaidController{ID: slotNumber(line, slot), Model: ssacliModel(line)}
		case cur != nil && strings.HasPrefix(strings.ToLower(line), "logicaldrive "):
			cur.VirtualDrives = append(cur.VirtualDrives, ssacliLogicalDrive(line))
		case cur != nil && strings.HasPrefix(strings.ToLower(line), "physicaldrive "):
			cur.PhysicalDrives = append(cur.PhysicalDrives, ssacliPhysicalDrive(line))
		}
	}
	if cur != nil {
		ctrls = append(ctrls, *cur)
	}
	return ctrls
}

func ssacliModel(line string) string {
	if i := strings.Index(line, hwrPfxSlot); i > 0 {
		return strings.TrimSpace(line[:i])
	}
	return ""
}

func slotNumber(line string, fallback int) int {
	if i := strings.Index(line, hwrPfxSlot); i >= 0 {
		rest := strings.TrimSpace(line[i+len(hwrPfxSlot):])
		fields := strings.FieldsFunc(rest, func(r rune) bool { return r < '0' || r > '9' })
		if len(fields) > 0 {
			if n, err := strconv.Atoi(fields[0]); err == nil {
				return n
			}
		}
	}
	return fallback
}

// ssacliParen extracts the parenthesized attribute list from a drive line.
func ssacliParen(line string) string {
	if i := strings.Index(line, "("); i >= 0 {
		if j := strings.LastIndex(line, ")"); j > i {
			return line[i+1 : j]
		}
	}
	return ""
}

func ssacliLogicalDrive(line string) models.HWRaidVD {
	name := strings.TrimSpace(strings.SplitN(line, "(", 2)[0])
	vd := models.HWRaidVD{Name: name}
	parts := strings.Split(ssacliParen(line), ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToUpper(p), "RAID") {
			vd.RaidLevel = p
		}
	}
	status := ""
	if len(parts) > 0 {
		status = strings.TrimSpace(parts[len(parts)-1])
	}
	applySsacliVDStatus(&vd, status)
	return vd
}

// applySsacliVDStatus maps HPE logical-drive status. "OK"; "Interim Recovery Mode" =
// degraded (running on a failed member); "Recovering"/"Rebuild" = rebuilding;
// hwrStatFailed = offline.
func applySsacliVDStatus(vd *models.HWRaidVD, status string) {
	s := strings.ToLower(status)
	switch {
	case s == "ok":
		vd.State = hwrStatOptimal
	case strings.Contains(s, "interim recovery") || strings.Contains(s, "degrad"):
		vd.State, vd.Degraded = "Degraded", true
	case strings.Contains(s, "recover") || strings.Contains(s, hwrKwRebuild) || strings.Contains(s, "expand"):
		vd.State, vd.Rebuilding = hwrStatRebuilt, true
	case strings.Contains(s, hwrKwFail):
		vd.State, vd.Offline = hwrStatOffline, true
	default:
		vd.State = status
	}
}

func ssacliPhysicalDrive(line string) models.HWRaidPD {
	fields := strings.Fields(line)
	loc := ""
	if len(fields) > 1 {
		loc = fields[1]
	}
	pd := models.HWRaidPD{Location: loc}
	parts := strings.Split(ssacliParen(line), ",")
	status := ""
	if len(parts) > 0 {
		status = strings.TrimSpace(parts[len(parts)-1])
	}
	applySsacliPDStatus(&pd, status)
	return pd
}

func applySsacliPDStatus(pd *models.HWRaidPD, status string) {
	s := strings.ToLower(status)
	switch {
	case s == "ok":
		pd.State = "Online"
	case strings.Contains(s, "predictive"):
		pd.State, pd.Predictive = "Predictive Failure", true
	case strings.Contains(s, hwrKwRebuild):
		pd.State, pd.Rebuilding = hwrStatRebuilt, true
	case strings.Contains(s, hwrKwFail):
		pd.State, pd.Failed = hwrStatFailed, true
	default:
		pd.State = status
	}
}
