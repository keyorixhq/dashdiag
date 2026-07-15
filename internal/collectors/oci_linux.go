//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// OCICollector reports guest-side health for a Linux instance on Oracle Cloud
// Infrastructure: IMDS v2 security posture, oracle-cloud-agent health, time
// sync against OCI's metadata NTP server, and VNIC ring-buffer drop counters.
// All work is gated behind OCIGuestAvailable() so it is zero-cost and silent on
// every host that is not an OCI instance. Scope is strictly guest-side, no OCI
// API credentials. Block-volume iSCSI session health is intentionally NOT
// duplicated here — ISCSICollector already covers it for every host.
type OCICollector struct{}

func NewOCICollector() *OCICollector { return &OCICollector{} }

func (c *OCICollector) Name() string { return "OCI" }

// 5s budget: the IMDS probes are each capped at 2s (instant on a real instance),
// and the systemctl/chronyc/ethtool reads are all local and fast.
func (c *OCICollector) Timeout() time.Duration { return 5 * time.Second }

// OCIGuestAvailable reports whether this host is a Linux OCI instance. Cheap
// gate (same shape as the AWS/Azure/GCP gates): a single world-readable DMI
// field, no root, no command execution.
func OCIGuestAvailable() bool {
	return isOCIGuest(readFileTrimmedLocal(filepath.Join(dmiIDDir, "chassis_asset_tag")))
}

// isOCIGuest matches OCI's DMI signature. chassis_asset_tag is "OracleCloud.com"
// on every OCI compute shape (bare metal and VM) — the documented, stable marker
// Oracle's own guest images key off.
func isOCIGuest(chassisAssetTag string) bool {
	return strings.EqualFold(strings.TrimSpace(chassisAssetTag), "OracleCloud.com")
}

func (c *OCICollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.OCIInfo{IsOCI: true}

	info.Shape, info.Region, info.AvailabilityDomain = ociInstanceMeta(ctx)
	info.IMDSChecked, info.IMDSv1Open = ociIMDSv1Open(ctx)
	info.AgentChecked, info.AgentInstalled, info.AgentRunning, info.AgentUpdaterRunning = ociAgentState(ctx)

	info.TimeSyncChecked, info.UsesOCITimeSync = ociTimeSyncConfigured()
	if info.UsesOCITimeSync {
		info.TimeSynced = ociTimeSynced(ctx)
	}

	info.VNICChecked, info.VNICs = ociVNICRingStats(ctx)

	return info, nil
}

// ---------- instance metadata (IMDS v2) ----------

// ociInstanceDoc mirrors the subset of OCI's /opc/v2/instance/ document this
// package needs; the real document has many more fields (tags, image OCID,
// shapeConfig, ...) that are out of scope here.
type ociInstanceDoc struct {
	ID                  string `json:"id"` // instance OCID
	Shape               string `json:"shape"`
	CanonicalRegionName string `json:"canonicalRegionName"`
	AvailabilityDomain  string `json:"availabilityDomain"`
}

// ociInstanceDocRead fetches and parses OCI's IMDS v2 instance document, nil on
// any error/unreachable IMDS.
func ociInstanceDocRead(ctx context.Context) *ociInstanceDoc {
	body, err := imdsGet(ctx, "http://169.254.169.254/opc/v2/instance/",
		map[string]string{"Authorization": "Bearer Oracle"})
	if err != nil || body == "" {
		return nil
	}
	var doc ociInstanceDoc
	if json.Unmarshal([]byte(body), &doc) != nil {
		return nil
	}
	return &doc
}

// ociInstanceMeta reads shape/region/availability-domain from IMDS v2. Empty
// strings on any error — this is recognition/context, never a verdict input.
func ociInstanceMeta(ctx context.Context) (shape, region, ad string) {
	doc := ociInstanceDocRead(ctx)
	if doc == nil {
		return "", "", ""
	}
	return doc.Shape, doc.CanonicalRegionName, doc.AvailabilityDomain
}

// ociIMDSv1Open probes whether OCI's IMDS still accepts a request WITHOUT the
// "Authorization: Bearer Oracle" header IMDS v2 requires. A token-less GET that
// succeeds (HTTP 200) means legacy/unauthenticated access is still reachable —
// the same SSRF-exposure class as AWS's IMDSv1-open finding (a properly
// configured instance returns 403). checked is false when IMDS itself was
// unreachable, so we never imply a posture we couldn't read.
func ociIMDSv1Open(ctx context.Context) (checked, open bool) {
	return probeIMDSOpen(ctx, "oci-imdsv1-probe", "http://169.254.169.254/opc/v2/instance/")
}

// ---------- oracle-cloud-agent ----------

// ociAgentState reports oracle-cloud-agent's install/run state, and whether its
// updater is running. checked is false when systemd itself couldn't answer
// (e.g. not a systemd host), so we never claim a posture we couldn't read.
func ociAgentState(ctx context.Context) (checked, installed, running, updaterRunning bool) {
	loadState, activeState := ociServiceState(ctx, "oracle-cloud-agent.service")
	if loadState == "" {
		return false, false, false, false
	}
	checked = true
	installed = loadState == "loaded"
	running = activeState == "active"
	_, updActiveState := ociServiceState(ctx, "oracle-cloud-agent-updater.service")
	updaterRunning = updActiveState == "active"
	return checked, installed, running, updaterRunning
}

// ociServiceState reads a systemd unit's LoadState/ActiveState via `systemctl
// show`, which always exits 0 and reports LoadState=not-found for a genuinely
// absent unit — unlike `systemctl is-active`, which returns the same non-zero
// exit for both "inactive" and "unit does not exist".
func ociServiceState(ctx context.Context, unit string) (loadState, activeState string) {
	out, err := runCmd(ctx, "systemctl", "show", unit, "-p", "LoadState,ActiveState", "--value")
	if err != nil {
		return "", ""
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		return "", ""
	}
	return strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1])
}

// ---------- time sync against OCI's metadata NTP server ----------

// ociTimeSyncConfigured reports whether NTP is configured against OCI's
// metadata NTP server (169.254.169.254) — mirrors AWS's Amazon Time Sync
// check. checked is false when no chrony/timesyncd config was found to read.
func ociTimeSyncConfigured() (checked, configured bool) {
	files := []string{
		"/etc/chrony.conf",
		"/etc/chrony/chrony.conf",
		"/etc/systemd/timesyncd.conf",
	}
	globs := []string{
		"/etc/chrony/conf.d/*.conf",
		"/etc/chrony/sources.d/*.sources",
		"/etc/chrony.d/*.conf",
		"/etc/chrony.d/*.sources",
		"/run/chrony.d/*.sources",
		"/etc/systemd/timesyncd.conf.d/*.conf",
	}
	for _, pat := range globs {
		if matches, err := curSource().Glob(pat); err == nil {
			files = append(files, matches...)
		}
	}
	for _, f := range files {
		body := readFileTrimmedLocal(f)
		if body == "" {
			continue
		}
		checked = true
		if strings.Contains(body, "169.254.169.254") {
			return true, true
		}
	}
	return checked, false
}

// ociTimeSynced reports whether chrony shows an actively selected/synced
// source against OCI's metadata NTP server. Configured-but-unreachable is a
// real gap config-file inspection alone can't see (e.g. a security-list change
// blocking the link-local NTP path).
func ociTimeSynced(ctx context.Context) bool {
	out, err := runCmd(ctx, "chronyc", "sources")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "^*") && strings.Contains(line, "169.254.169.254") {
			return true
		}
	}
	return false
}

// ---------- VNIC ring health ----------

// ociVNICRingStats reads ring-buffer drop/timeout counters for every
// virtio_net interface (OCI's standard paravirtualized VNIC driver).
func ociVNICRingStats(ctx context.Context) (checked bool, vnics []models.OCIVNIC) {
	drivers, _ := collectNICDrivers("/sys/class/net")
	for iface, drv := range drivers {
		if !strings.EqualFold(drv, "virtio_net") {
			continue
		}
		out, err := runCmd(ctx, "ethtool", "-S", iface)
		if err != nil {
			continue
		}
		checked = true
		rxDrops, txTimeouts := parseVirtioRingCounters(out)
		vnics = append(vnics, models.OCIVNIC{
			Iface: iface, Driver: drv, RxDrops: rxDrops, TxTimeouts: txTimeouts,
		})
	}
	sortOCIVNICs(vnics)
	return checked, vnics
}

// parseVirtioRingCounters reads the aggregate rx_drops/tx_tx_timeouts counters
// from `ethtool -S` output for a virtio_net interface. Deliberately does NOT
// also sum the per-queue rxN_drops/txN_tx_timeouts siblings virtio_net exposes
// alongside them — verified live (single-queue A1.Flex shape) that the
// aggregate and per-queue-0 values are the same counter, so summing both would
// double-count. Multi-queue (multiple vCPU) behavior is unverified; if the
// aggregate key is ever absent on such a shape this deliberately reads as 0
// rather than guessing at an unverified summation.
func parseVirtioRingCounters(out string) (rxDrops, txTimeouts uint64) {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSpace(k) {
		case "rx_drops":
			rxDrops = n
		case "tx_tx_timeouts":
			txTimeouts = n
		}
	}
	return rxDrops, txTimeouts
}

func sortOCIVNICs(v []models.OCIVNIC) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j].Iface < v[j-1].Iface; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
