//go:build linux

package collectors

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// AzureCollector reports guest-side health for a Linux VM on Azure: the
// Accelerated-Networking SR-IOV datapath, Hyper-V synthetic drivers, the Azure Linux
// agent (waagent), and the Hyper-V PTP time source. All work is gated behind
// AzureGuestAvailable() so it is zero-cost and silent on every non-Azure host. Scope
// is strictly guest-side, no Azure API credentials — everything is read from sysfs,
// local config, and process/service state.
type AzureCollector struct{}

func NewAzureCollector() *AzureCollector { return &AzureCollector{} }

func (c *AzureCollector) Name() string           { return "Azure" }
func (c *AzureCollector) Timeout() time.Duration { return 3 * time.Second }

// azureChassisAssetTag is Azure's documented chassis asset tag — the one DMI marker
// that distinguishes an Azure VM from an on-prem Hyper-V guest (which shares the
// "Microsoft Corporation" / "Virtual Machine" sys_vendor/product_name). Kept in sync
// with platform.detectCloudEnvironment.
const azureChassisAssetTag = "7783-7084-3265-9085-8269-3286-77"

// AzureGuestAvailable reports whether this host is a Linux VM on Azure. Cheap gate
// (same shape as VMwareGuestAvailable/AWSGuestAvailable): world-readable DMI strings,
// no root, no command execution. The asset tag is the trusted differentiator from
// on-prem Hyper-V.
func AzureGuestAvailable() bool {
	return isAzureGuest(
		readFileTrimmedLocal(filepath.Join(dmiIDDir, "sys_vendor")),
		readFileTrimmedLocal(filepath.Join(dmiIDDir, "product_name")),
		readFileTrimmedLocal(filepath.Join(dmiIDDir, "chassis_asset_tag")),
	)
}

// isAzureGuest matches Azure's DMI signature. The chassis asset tag is definitive;
// the literal "microsoft azure" string is a secondary marker. "Microsoft Corporation"
// + "Virtual Machine" alone is NOT trusted — it matches every on-prem Hyper-V VM too.
func isAzureGuest(sysVendor, productName, assetTag string) bool {
	if strings.TrimSpace(assetTag) == azureChassisAssetTag {
		return true
	}
	hay := strings.ToLower(sysVendor + " " + productName + " " + assetTag)
	return strings.Contains(hay, "microsoft azure")
}

func (c *AzureCollector) Collect(_ context.Context) (interface{}, error) {
	info := &models.AzureInfo{IsAzure: true}

	info.SyntheticNICs, info.AN, info.HasVF = collectAcceleratedNetworking("/sys/class/net")

	mods := readFileTrimmedLocal("/proc/modules")
	info.NetvscLoaded = kernelModulePresent(mods, "hv_netvsc")
	info.StorvscLoaded = kernelModulePresent(mods, "hv_storvsc")
	info.VMBusLoaded = kernelModulePresent(mods, "hv_vmbus")

	info.WAAgentInstalled, info.WAAgentRunning = waagentState()
	info.TimeSyncChecked, info.UsesHyperVPTP = azureTimeSyncConfigured()

	return info, nil
}

// ---------- Accelerated Networking (SR-IOV VF datapath) ----------

// acceleratedVFDrivers are the NIC drivers Azure uses for an Accelerated-Networking
// VF: Mellanox ConnectX (mlx4/mlx5) and the newer Microsoft Azure Network Adapter.
func acceleratedVFDriver(driver string) bool {
	switch strings.ToLower(driver) {
	case "mlx5_core", "mlx4_en", "mlx4_core", "mana", "mana_en":
		return true
	default:
		return false
	}
}

// collectAcceleratedNetworking inspects the NIC topology for Azure's transparent-
// bonding model: synthetic hv_netvsc NICs and the accelerated VFs slaved under them.
// It reports the synthetic NICs, the per-VF state, and whether any VF was found at
// all. A VF discovered via a synthetic NIC's "lower_*" link is marked bonded; an
// accelerated-driver NIC with no such link is reported unbonded (the failure shape).
func collectAcceleratedNetworking(netDir string) (synthetics []string, ifaces []models.ANIface, hasVF bool) {
	drivers, _ := collectNICDrivers(netDir)
	for iface, drv := range drivers {
		if strings.EqualFold(drv, "hv_netvsc") {
			synthetics = append(synthetics, iface)
		}
	}
	sort.Strings(synthetics)

	bonded := map[string]bool{}
	for _, syn := range synthetics {
		for _, vf := range lowerInterfaces(netDir, syn) {
			bonded[vf] = true
			ifaces = append(ifaces, models.ANIface{
				VF: vf, Driver: drivers[vf], Synthetic: syn,
				Bonded: true, Up: nicOperstateUp(netDir, vf),
			})
			hasVF = true
		}
	}
	// Accelerated VFs that exist but are NOT slaved under a synthetic NIC — the
	// "VF present but datapath not wired up" failure the heuristic flags.
	for iface, drv := range drivers {
		if acceleratedVFDriver(drv) && !bonded[iface] {
			ifaces = append(ifaces, models.ANIface{
				VF: iface, Driver: drv, Bonded: false, Up: nicOperstateUp(netDir, iface),
			})
			hasVF = true
		}
	}
	sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].VF < ifaces[j].VF })
	return synthetics, ifaces, hasVF
}

// lowerInterfaces returns the interfaces enslaved under iface, read from the
// "lower_<name>" symlinks the kernel creates in /sys/class/net/<iface>/.
func lowerInterfaces(netDir, iface string) []string {
	entries, err := readDirEntries(filepath.Join(netDir, iface))
	if err != nil {
		return nil
	}
	var lowers []string
	for _, e := range entries {
		if name := strings.TrimPrefix(e.Name(), "lower_"); name != e.Name() {
			lowers = append(lowers, name)
		}
	}
	return lowers
}

// nicOperstateUp reports whether an interface's operstate is "up".
func nicOperstateUp(netDir, iface string) bool {
	return readFileTrimmedLocal(filepath.Join(netDir, iface, "operstate")) == "up"
}

// ---------- Azure Linux Agent (waagent) ----------

// waagentState reports whether the Azure Linux agent is installed and running.
// Installed-but-not-running is the actionable case (extensions / provisioning /
// password reset are silently broken); not-installed is silent (some images use
// cloud-init only). The agent runs as a python process, so service state is checked
// via systemctl (walinuxagent on Debian/Ubuntu, waagent on RHEL/SUSE) rather than by
// process name.
func waagentState() (installed, running bool) {
	if _, err := lookPath("waagent"); err == nil {
		installed = true
	}
	for _, p := range []string{"/usr/sbin/waagent", "/usr/bin/waagent", "/var/lib/waagent"} {
		if fileExists(p) {
			installed = true
			break
		}
	}
	if !installed {
		return false, false
	}
	for _, unit := range []string{"walinuxagent", "waagent"} {
		if out, err := runCmd(context.Background(), "systemctl", "is-active", unit); err == nil &&
			strings.TrimSpace(out) == "active" {
			return true, true
		}
	}
	return true, false
}

// ---------- Hyper-V PTP time source ----------

// azureTimeSyncConfigured reports whether the NTP client is using the Hyper-V PTP
// clock (/dev/ptp_hyperv, Azure's recommended low-drift source) as a PHC refclock.
// checked is false when no chrony/timesyncd config was found to read, so we never
// claim a verdict on a host whose time config we couldn't see.
func azureTimeSyncConfigured() (checked, uses bool) {
	files := []string{
		"/etc/chrony.conf",
		"/etc/chrony/chrony.conf",
		"/etc/systemd/timesyncd.conf",
	}
	for _, pat := range []string{"/etc/chrony/conf.d/*.conf", "/etc/chrony/sources.d/*.sources"} {
		if matches, err := activeSource.Glob(pat); err == nil {
			files = append(files, matches...)
		}
	}
	for _, f := range files {
		body := readFileTrimmedLocal(f)
		if body == "" {
			continue
		}
		checked = true
		low := strings.ToLower(body)
		if strings.Contains(low, "ptp_hyperv") || strings.Contains(low, "refclock phc") {
			return true, true
		}
	}
	return checked, false
}
