//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// nvmeUnreadReason classifies why `nvme smart-log` failed, so the heuristic can
// give correct remediation rather than always blaming a missing nvme-cli — or,
// conversely, telling a non-root operator to "re-run as root" when sudo cannot
// help because nvme-cli is not installed at all.
//
// Genuine ABSENCE is checked first, via sbinToolPath rather than a plain
// lookPath: on many distros (SUSE, RHEL) the `nvme` binary lives in /usr/sbin,
// which a non-root $PATH omits, so a bare lookPath would wrongly report "absent"
// for an installed tool — sbinToolPath also probes the sbin dirs, so a miss
// there means the binary truly is not on the box. Only once we know the tool
// exists does privilege become the explanation: the smart-log ioctl is
// root-gated, so a non-root failure with the tool present is "needs root".
// (Validated 2026-06-25 on an arm64 Debian 13 EC2 box where nvme-cli was absent
// yet the non-root run wrongly told the operator to sudo; and earlier on SLES 16
// arm64 where nvme-cli was present in /usr/sbin and must NOT read as absent.)
func nvmeUnreadReason() string {
	if sbinToolPath("nvme") == "" {
		return "tool_absent"
	}
	if geteuid() != 0 {
		return "needs_root"
	}
	return "error"
}

// NVMeCollector reads NVMe SMART health via `nvme smart-log`.
// nvme-cli is an acceptable wrapper — raw SMART ioctl requires CGO.
type NVMeCollector struct{}

func NewNVMeCollector() *NVMeCollector { return &NVMeCollector{} }

func (c *NVMeCollector) Name() string           { return "Drives" }
func (c *NVMeCollector) Timeout() time.Duration { return 8 * time.Second }

func (c *NVMeCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.NVMeInfo{}

	// Find all NVMe controllers
	controllers, _ := glob("/sys/class/nvme/nvme*")
	for _, ctrl := range controllers {
		// Only controllers (nvme0, nvme10, …) — skip namespaces (nvme0n1) and
		// multipath instances (nvme0c0n1).
		base := filepath.Base(ctrl)
		if !isNVMeController(base) {
			continue
		}

		dev := &models.NVMeDevice{
			Name:  "/dev/" + base,
			Model: strings.TrimSpace(readFileStr(filepath.Join(ctrl, "model"))),
			State: strings.TrimSpace(readFileStr(filepath.Join(ctrl, "state"))),
		}

		// Read SMART log via nvme-cli
		out, err := runCmd(ctx, "nvme", "smart-log", dev.Name, "--output-format=normal")
		if err != nil {
			// SMART unread — record WHY so the heuristic gives the right
			// remediation instead of a blanket "nvme-cli not installed".
			dev.SmartUnreadReason = nvmeUnreadReason()
			info.Devices = append(info.Devices, *dev)
			continue
		}

		// SmartRead only when smart-log actually yielded a recognized field — an
		// exit-0 run with unparseable output must NOT mark the all-zero health fields
		// as real (which would read as a healthy drive).
		dev.SmartRead = parseNVMeSmartLog(out, dev)
		if !dev.SmartRead {
			// nvme-cli ran (exit 0) but its output was unparseable (banner-only /
			// unexpected format). Mark it "error", not the empty default — else the
			// heuristic gives the wrong "nvme-cli not installed" hint for a tool that
			// clearly IS installed and just ran.
			dev.SmartUnreadReason = "error"
		}

		// Detect mount points from /proc/mounts
		dev.MountPoints, dev.HasLinux = nvmeMountPoints(base)

		info.Devices = append(info.Devices, *dev)
	}

	// Also detect SATA/SAS drives via smartctl
	collectSATADrives(ctx, info)

	if len(info.Devices) == 0 && len(info.SATADevices) == 0 {
		// No NVMe controllers and no SMART-capable SATA/SAS drives — typical of
		// cloud/KVM guests on virtio disks. Nothing to report; gate off rather
		// than emit a phantom "NVMe ✅ OK" row.
		return nil, nil
	}
	return info, nil
}

// parseNVMeSmartLog parses `nvme smart-log` output into NVMeDevice fields and
// returns whether ANY recognized SMART field was actually parsed. The caller uses
// that to set SmartRead: `nvme smart-log` can exit 0 yet emit nothing parseable
// (unexpected format / a tool that printed only a banner), and blindly setting
// SmartRead=true left the all-zero health fields reading as a healthy drive.
func parseNVMeSmartLog(out string, dev *models.NVMeDevice) bool {
	parsedAny := false
	sawCriticalWarning := false
	sawMediaErrors := false
	sawPercentageUsed := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "critical_warning":
			dev.CriticalWarning = parseBitmask(val)
			sawCriticalWarning = true
		case "temperature":
			// Format: "111 °F (317 K)" — extract Kelvin and convert
			dev.TempC = parseNVMeTemp(val)
		case "available_spare":
			dev.AvailableSparePct = parseInt(strings.TrimSuffix(val, "%"))
		case "available_spare_threshold":
			dev.SpareThresholdPct = parseInt(strings.TrimSuffix(val, "%"))
		case "percentage_used":
			dev.PercentageUsed = parseInt(strings.TrimSuffix(val, "%"))
			sawPercentageUsed = true
		case "media_errors":
			dev.MediaErrors = parseInt64(val)
			sawMediaErrors = true
		case "unsafe_shutdowns":
			dev.UnsafeShutdowns = parseInt64(val)
		case "power_on_hours":
			dev.PowerOnHours = parseInt64(val)
		case "power_cycles":
			dev.PowerCycles = parseInt64(val)
		default:
			continue // unrecognized key — don't count as a successful parse
		}
		parsedAny = true // reached only when a known case matched
	}
	// internal-collectors-24-01: parsedAny (and so SmartRead) goes true on ANY
	// single recognized field — a smart-log that includes only a benign field
	// like power_on_hours, while critical_warning/media_errors/percentage_used
	// are missing or garbled, must not read as a fully-verified healthy drive.
	dev.SmartDangerousFieldsUnread = !sawCriticalWarning || !sawMediaErrors || !sawPercentageUsed
	return parsedAny
}

// parseNVMeTemp extracts temperature in Celsius from nvme smart-log output.
// Format: "111 °F (317 K)" — Kelvin is most reliable.
func parseNVMeTemp(s string) float64 {
	// Try to find Kelvin value in parentheses
	open := strings.LastIndex(s, "(")
	close := strings.LastIndex(s, " K)")
	if open >= 0 && close > open {
		kelvinStr := strings.TrimSpace(s[open+1 : close])
		if k, err := strconv.ParseFloat(kelvinStr, 64); err == nil && k > 0 && !math.IsInf(k, 0) {
			return k - 273.15
		}
	}
	// Fallback: parse Celsius directly if available. Guard NaN/Inf — "nan"/"inf"
	// are valid ParseFloat syntax (no error), and a NaN/Inf temperature would
	// corrupt the `temp >= N` thermal verdict (NaN→false→false-OK, Inf→false CRIT).
	fields := strings.Fields(s)
	if len(fields) > 0 {
		if c, err := strconv.ParseFloat(fields[0], 64); err == nil && !math.IsNaN(c) && !math.IsInf(c, 0) {
			return c
		}
	}
	return 0
}

// nvmeMountPoints reads /proc/mounts and returns all mount points for partitions
// of the given NVMe controller (e.g. "nvme0" → checks nvme0n1p1, nvme0n1p2 etc).
// Also returns true if any mounted filesystem is a Linux fs (xfs, ext4, btrfs etc).
func nvmeMountPoints(ctrlBase string) ([]string, bool) {
	// ctrlBase is like "/sys/class/nvme/nvme0" → device prefix is "nvme0"
	devPrefix := filepath.Base(ctrlBase) // "nvme0"

	data, err := readFile("/proc/mounts")
	if err != nil {
		return nil, false
	}

	linuxFS := map[string]bool{
		"xfs": true, "ext4": true, "ext3": true, "ext2": true,
		"btrfs": true, "f2fs": true, "jfs": true, "reiserfs": true,
	}

	var mounts []string
	hasLinux := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		dev := filepath.Base(fields[0]) // e.g. "nvme0n1p3"
		mountPoint := fields[1]
		fsType := fields[2]

		// Match any partition of this controller (nvme0n1p*, nvme0n2p* etc)
		if !strings.HasPrefix(dev, devPrefix) {
			continue
		}
		if mountPoint == "none" || mountPoint == "swap" {
			continue
		}
		mounts = append(mounts, mountPoint)
		if linuxFS[fsType] {
			hasLinux = true
		}
	}
	return mounts, hasLinux
}

func readFileStr(path string) string {
	data, err := readFile(filepath.Clean(path)) // #nosec G304 -- path from sysfs glob
	if err != nil {
		return ""
	}
	return string(data)
}

// parseBitmask parses an nvme `critical_warning` value. `nvme smart-log
// --output-format=normal` prints this field as %#x (verified in nvme-cli 2.13),
// so a NON-ZERO warning arrives hex-encoded ("0x4") while zero prints plain "0".
// strconv.Atoi chokes on the "0x" form and returned 0 — silently clearing a real
// warning (spare-exhausted / reliability-degraded / read-only / backup-failed
// bits) so a failing drive read as healthy at heuristics.go's `CriticalWarning >
// 0`. Base 0 auto-detects 0x; decimal still parses. Negative/garbled → 0.
func parseBitmask(s string) int {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.ParseInt(fields[0], 0, 64)
	if err != nil || v < 0 {
		return 0
	}
	return int(v)
}

// parseInt / parseInt64 read a SMART numeric attribute. They reject negative or
// garbled values (→ 0): a negative count would slip under the `> 0` / `>= N`
// failure thresholds in analysis/heuristics.go as a false-OK (mirrors the
// smartctl path's guard; same bug class as PR #200).
func parseInt(s string) int {
	// Handle values like "60783741 (31.12 TB)"
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.Atoi(fields[0])
	if err != nil || v < 0 {
		return 0
	}
	return v
}

func parseInt64(s string) int64 {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

// collectSATADrives detects SATA/SAS drives via smartctl --scan and reads SMART data.
// Gracefully skips if smartctl is not installed.
func collectSATADrives(ctx context.Context, info *models.NVMeInfo) {
	out, err := runCmd(ctx, "smartctl", "--scan-open", "--json=c")
	if err != nil || out == "" {
		return // smartctl not installed or no drives
	}

	var scan struct {
		Devices []struct {
			Name      string `json:"name"`
			Type      string `json:"type"`
			Protocol  string `json:"protocol"`
			OpenError string `json:"open_error"`
		} `json:"devices"`
	}
	if err := jsonUnmarshal([]byte(out), &scan); err != nil {
		return
	}

	for _, d := range scan.Devices {
		// Skip NVMe — already handled above
		proto := strings.ToLower(d.Protocol)
		if strings.Contains(proto, "nvme") {
			continue
		}

		dev := models.SATADevice{Name: d.Name}
		switch {
		case strings.Contains(proto, "ata") || strings.Contains(proto, "sata"):
			dev.Type = "sata"
		case strings.Contains(proto, "scsi") || strings.Contains(proto, "sas"):
			dev.Type = "sas"
		default:
			dev.Type = proto
		}

		// `--scan-open` reports a per-device open_error when it couldn't open the
		// device. Classify from it directly: the follow-up `-a` exits non-zero and
		// runCmd drops its stdout, so the permission message would otherwise be lost
		// and a non-root read mis-classified as a generic "error". A permission
		// failure → needs_root ("re-run as root"); any other open error → error.
		if d.OpenError != "" {
			dev.Error = "smartctl: " + d.OpenError
			if strings.Contains(strings.ToLower(d.OpenError), "permission denied") {
				dev.SmartUnreadReason = "needs_root"
			} else {
				dev.SmartUnreadReason = "error"
			}
			info.SATADevices = append(info.SATADevices, dev)
			continue
		}

		// Read SMART data
		smartOut, err := runCmd(ctx, "smartctl", "--json=c", "-a", d.Name)
		if err != nil && smartOut == "" {
			dev.Error = "smartctl failed"
			dev.SmartUnreadReason = "error"
			info.SATADevices = append(info.SATADevices, dev)
			continue
		}

		applySATASmartJSON(smartOut, &dev)
		info.SATADevices = append(info.SATADevices, dev)
	}
}

// applySATASmartJSON parses `smartctl --json=c -a` output into a SATADevice.
// smart_status.passed is read through a *bool so a MISSING verdict (smartctl
// emits JSON with no smart_status for USB bridges / RAID members / virtual
// disks) is distinguished from an explicit "not passed". dev.SmartRead is set
// only when the verdict is actually present, so the analysis layer never fires
// a "drive may be failing" CRIT on a drive whose SMART was simply never read.
func applySATASmartJSON(out string, dev *models.SATADevice) {
	var smart struct {
		Smartctl struct {
			Messages []struct {
				String string `json:"string"`
			} `json:"messages"`
		} `json:"smartctl"`
		ModelName   string `json:"model_name"`
		SmartStatus *struct {
			Passed bool `json:"passed"`
		} `json:"smart_status"`
		Temperature struct {
			Current int `json:"current"`
		} `json:"temperature"`
		PowerOnTime struct {
			Hours int64 `json:"hours"`
		} `json:"power_on_time"`
		ATAAttributes *struct {
			Table []struct {
				ID  int `json:"id"`
				Raw struct {
					Value int64 `json:"value"`
				} `json:"raw"`
			} `json:"table"`
		} `json:"ata_smart_attributes,omitempty"`
	}
	if err := jsonUnmarshal([]byte(out), &smart); err != nil {
		return // not JSON / garbled — SmartRead stays false, no false verdict
	}
	dev.Model = smart.ModelName
	dev.TempC = smart.Temperature.Current
	dev.PowerOnHours = smart.PowerOnTime.Hours
	if smart.SmartStatus != nil {
		dev.SmartRead = true
		dev.SmartOK = smart.SmartStatus.Passed
	} else {
		// smartctl ran but emitted no SMART verdict. Classify WHY from its own
		// message stream (`--json=c` reports errors there even on failure) so the
		// analysis layer can tell "re-run as root" from "this device exposes no
		// SMART" (virtual disk / USB bridge / RAID-HBA member). A permission error
		// only appears unprivileged; a virtual disk reads SMART-less even as root.
		dev.SmartUnreadReason = "no_smart"
		for _, m := range smart.Smartctl.Messages {
			if strings.Contains(strings.ToLower(m.String), "permission denied") {
				dev.SmartUnreadReason = "needs_root"
				break
			}
		}
	}
	if smart.ATAAttributes != nil {
		for _, attr := range smart.ATAAttributes.Table {
			switch attr.ID {
			case 5:
				dev.ReallocatedSectors = int(attr.Raw.Value)
			case 197:
				dev.PendingSectors = int(attr.Raw.Value)
			case 198:
				dev.UncorrectableErrors = int(attr.Raw.Value)
			}
		}
	}
}

// jsonUnmarshal is a thin wrapper so we don't import encoding/json twice.
func jsonUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
