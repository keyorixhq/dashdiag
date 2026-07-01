//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
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
		if os.Geteuid() != 0 {
			info.Available, info.NeedsRoot = true, true
			return info, nil
		}
		info.Available, info.ReadFailed = true, true
		return info, nil
	}

	if family {
		info.Controllers = parseSsacli(out)
	} else {
		info.Controllers = parseStorcli(out)
	}

	// Tool installed but no controller responded (e.g. "No Controller found", or the
	// box has the CLI but no card). Gate off — nothing to report.
	if len(info.Controllers) == 0 {
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
func parseStorcli(out string) []models.HWRaidController {
	var doc storcliOutput
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil
	}
	var ctrls []models.HWRaidController
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
		ctrl.BBUStatus, ctrl.BBUDegraded = storcliBBU(c.ResponseData.BBUInfo, c.ResponseData.CachevaultInfo)
		ctrls = append(ctrls, ctrl)
	}
	return ctrls
}

// normalizeStorcliVD maps storcli's abbreviated VD states. Optl=Optimal, Dgrd=Degraded,
// Pdgd=Partially Degraded, OfLn=Offline, Rec=Recovery (rebuilding).
func normalizeStorcliVD(name string, vd storcliVD) models.HWRaidVD {
	s := strings.ToLower(strings.TrimSpace(vd.State))
	out := models.HWRaidVD{Name: name, RaidLevel: vd.Type}
	switch {
	case s == "optl" || strings.HasPrefix(s, "optimal"):
		out.State = "Optimal"
	case s == "dgrd" || strings.HasPrefix(s, "degrad"):
		out.State, out.Degraded = "Degraded", true
	case s == "pdgd" || strings.HasPrefix(s, "partially"):
		out.State, out.Degraded = "Partially Degraded", true
	case s == "ofln" || strings.HasPrefix(s, "offl"):
		out.State, out.Offline = "Offline", true
	case s == "rec" || strings.HasPrefix(s, "recov") || strings.HasPrefix(s, "rebuild"):
		out.State, out.Rebuilding = "Rebuilding", true
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
	case s == "rbld" || strings.HasPrefix(s, "rebuild"):
		out.State, out.Rebuilding = "Rebuilding", true
	case s == "failed" || s == "ubad" || strings.HasPrefix(s, "fail"):
		out.State, out.Failed = "Failed", true
	case s == "offln" || strings.HasPrefix(s, "offl"):
		out.State, out.Failed = "Offline", true
	default:
		out.State = pd.State
	}
	return out
}

func storcliBBU(bbu, cv []struct {
	State string `json:"State"`
}) (string, bool) {
	state := ""
	if len(bbu) > 0 {
		state = bbu[0].State
	} else if len(cv) > 0 {
		state = cv[0].State
	}
	if state == "" {
		return "", false
	}
	// "Optimal" is the healthy state for both BBU and CacheVault.
	return state, !strings.EqualFold(strings.TrimSpace(state), "Optimal")
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
		case strings.Contains(line, " in Slot "):
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
	if i := strings.Index(line, " in Slot "); i > 0 {
		return strings.TrimSpace(line[:i])
	}
	return ""
}

func slotNumber(line string, fallback int) int {
	if i := strings.Index(line, " in Slot "); i >= 0 {
		rest := strings.TrimSpace(line[i+len(" in Slot "):])
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
// "Failed" = offline.
func applySsacliVDStatus(vd *models.HWRaidVD, status string) {
	s := strings.ToLower(status)
	switch {
	case s == "ok":
		vd.State = "Optimal"
	case strings.Contains(s, "interim recovery") || strings.Contains(s, "degrad"):
		vd.State, vd.Degraded = "Degraded", true
	case strings.Contains(s, "recover") || strings.Contains(s, "rebuild") || strings.Contains(s, "expand"):
		vd.State, vd.Rebuilding = "Rebuilding", true
	case strings.Contains(s, "fail"):
		vd.State, vd.Offline = "Offline", true
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
	case strings.Contains(s, "rebuild"):
		pd.State, pd.Rebuilding = "Rebuilding", true
	case strings.Contains(s, "fail"):
		pd.State, pd.Failed = "Failed", true
	default:
		pd.State = status
	}
}
