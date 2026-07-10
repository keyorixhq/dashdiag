//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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

func (c *AzureCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.AzureInfo{IsAzure: true}

	info.SyntheticNICs, info.AN, info.HasVF = collectAcceleratedNetworking("/sys/class/net")

	mods := readFileTrimmedLocal("/proc/modules")
	info.NetvscLoaded = kernelModulePresent(mods, "hv_netvsc")
	info.StorvscLoaded = kernelModulePresent(mods, "hv_storvsc")
	info.VMBusLoaded = kernelModulePresent(mods, "hv_vmbus")

	info.WAAgentInstalled, info.WAAgentRunning = waagentState()
	info.TimeSyncChecked, info.UsesHyperVPTP = azureTimeSyncConfigured()

	info.DynamicMemory, info.DynMemMaxMB = dynamicMemoryState(kernelModulePresent(mods, "hv_balloon"), azureDmesg(ctx))
	info.TempDiskPresent, info.TempDiskDevice, info.TempDiskMount, info.PersistentDataAtRisk = tempDiskStateFromHost()
	info.DisksChecked, info.Disks = azureDiskCaching(ctx)
	info.NVMePresent, info.NVMeIOTimeoutChecked, info.NVMeIOTimeoutSecs = azureNVMeIOTimeout()

	return info, nil
}

// ---------- NVMe I/O timeout (full-coverage tail) ----------

// azureNVMeIOTimeout reports the kernel's nvme_core.io_timeout when this VM has NVMe
// disks. present is false on a non-NVMe VM (so the check is silent there); checked is
// false when NVMe is present but the parameter could not be read or parsed, so an
// unreadable value never reads as "tuned".
func azureNVMeIOTimeout() (present, checked bool, secs int) {
	if !nvmeDevicesPresent("/sys/class/nvme") {
		return false, false, 0
	}
	raw := readFileTrimmedLocal("/sys/module/nvme_core/parameters/io_timeout")
	if raw == "" {
		return true, false, 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return true, false, 0
	}
	return true, true, n
}

// nvmeDevicesPresent reports whether any NVMe controller is registered under the given
// sysfs class dir (/sys/class/nvme on a live host).
func nvmeDevicesPresent(nvmeClassDir string) bool {
	entries, err := readDirEntries(nvmeClassDir)
	return err == nil && len(entries) > 0
}

// ---------- Dynamic Memory (Hyper-V ballooning) ----------

// dynamicMemoryState reports whether Hyper-V Dynamic Memory is enabled — the caller
// passes whether the hv_balloon driver is loaded — and the configured ceiling the
// kernel logged, if any. Driver presence is a confident guest-side fact. Ballooning
// *pressure* has no reliable guest-side counter, so it is deliberately NOT inferred
// here: claiming "memory pressure" off an unreadable signal would be exactly the
// false-alarm class dsd avoids. balloonLoaded is injected (not read here) so this stays
// a pure unit — kernelModulePresent has a /sys/module fallback that would otherwise
// couple a test to the host (a GitHub Azure-VM runner has /sys/module/hv_balloon).
func dynamicMemoryState(balloonLoaded bool, dmesg string) (enabled bool, maxMB int) {
	if !balloonLoaded {
		return false, 0
	}
	return true, parseHVBalloonMaxMB(dmesg)
}

var hvBalloonMaxRe = regexp.MustCompile(`hv_balloon:\s*Max\.\s*dynamic memory size:\s*(\d+)\s*MB`)

// parseHVBalloonMaxMB extracts N from a kernel line like
// "hv_balloon: Max. dynamic memory size: 8192 MB". Returns 0 if absent or garbled.
func parseHVBalloonMaxMB(dmesg string) int {
	m := hvBalloonMaxRe.FindStringSubmatch(dmesg)
	if m == nil {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// azureDmesg returns the kernel log best-effort (empty on dmesg_restrict / non-root /
// unreadable). The DM ceiling is a nice-to-have, never load-bearing — DynamicMemory is
// determined from /proc/modules, which needs no privilege.
func azureDmesg(ctx context.Context) string {
	out, err := runCmd(ctx, "dmesg")
	if err != nil {
		return ""
	}
	return out
}

// ---------- Resource (temp) disk ----------

// tempDiskStateFromHost reads the host inputs for tempDiskState: the WAAgent config
// (for the configured mount point), the live mount table, /etc/fstab, and the
// WAAgent-managed /dev/disk/azure/resource marker.
func tempDiskStateFromHost() (present bool, device, mount string, atRisk bool) {
	return tempDiskState(
		readFileTrimmedLocal("/etc/waagent.conf"),
		readFileTrimmedLocal("/proc/mounts"),
		readFileTrimmedLocal("/etc/fstab"),
		fileExists("/dev/disk/azure/resource"),
	)
}

var resourceMountRe = regexp.MustCompile(`(?m)^\s*ResourceDisk\.MountPoint\s*=\s*(\S+)`)

// tempDiskState locates Azure's ephemeral resource/temp disk and reports whether
// persistent data is layered onto it. Candidate mount points are the WAAgent-configured
// one (if any) then the two common defaults (/mnt/resource on agent images, /mnt on
// cloud-init images); the first with a live mount wins. Presence is also asserted by
// the /dev/disk/azure/resource marker even when nothing is mounted. atRisk is set when
// /etc/fstab mounts anything onto a subdirectory of the temp mount — the classic
// "persistent data on ephemeral storage, lost on host migration" footgun.
func tempDiskState(waagentConf, procMounts, fstab string, resourceLinkExists bool) (present bool, device, mount string, atRisk bool) {
	candidates := []string{}
	if m := resourceMountRe.FindStringSubmatch(waagentConf); m != nil {
		candidates = append(candidates, strings.TrimRight(m[1], "/"))
	}
	candidates = append(candidates, "/mnt/resource", "/mnt")

	for _, cand := range candidates {
		if dev := deviceMountedAt(procMounts, cand); dev != "" {
			device, mount = dev, cand
			present = true
			break
		}
	}
	if !present && resourceLinkExists {
		present = true
	}
	if mount != "" {
		atRisk = fstabHasSubmount(fstab, mount)
	}
	return present, device, mount, atRisk
}

// deviceMountedAt returns the device mounted at exactly mountPoint per /proc/mounts, or
// "" if nothing is mounted there.
func deviceMountedAt(procMounts, mountPoint string) string {
	for _, line := range strings.Split(procMounts, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == mountPoint {
			return f[0]
		}
	}
	return ""
}

// fstabHasSubmount reports whether /etc/fstab declares a mount whose target is a strict
// subdirectory of mount (e.g. a database datadir under the ephemeral /mnt). The temp
// mount line itself is not a submount and does not trip this.
func fstabHasSubmount(fstab, mount string) bool {
	prefix := strings.TrimRight(mount, "/") + "/"
	for _, line := range strings.Split(fstab, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 && strings.HasPrefix(f[1], prefix) {
			return true
		}
	}
	return false
}

// ---------- Managed-disk host caching (IMDS storageProfile) ----------

// azStorageProfile mirrors the IMDS compute/storageProfile node. Azure returns numeric
// fields (lun) as JSON strings, so Lun is decoded as a string and parsed.
type azStorageProfile struct {
	OSDisk struct {
		Name    string `json:"name"`
		Caching string `json:"caching"`
	} `json:"osDisk"`
	DataDisks []struct {
		Name    string `json:"name"`
		Lun     string `json:"lun"`
		Caching string `json:"caching"`
	} `json:"dataDisks"`
}

// azureDiskCaching reads the host-cache mode of each disk from the link-local IMDS
// storageProfile. checked is false on any IMDS/parse error so an unread profile never
// reads as "no caching problems".
func azureDiskCaching(ctx context.Context) (checked bool, disks []models.AzureDisk) {
	body, err := imdsGet(ctx,
		"http://169.254.169.254/metadata/instance/compute/storageProfile?api-version=2021-02-01&format=json",
		map[string]string{"Metadata": "true"})
	if err != nil || body == "" {
		return false, nil
	}
	return parseAzureStorageProfile(body)
}

// parseAzureStorageProfile turns the IMDS storageProfile JSON into the OS disk followed
// by each data disk, carrying the host-cache mode. checked is false when the body is
// not the expected JSON object (couldn't-measure, never a silent OK).
func parseAzureStorageProfile(body string) (checked bool, disks []models.AzureDisk) {
	var sp azStorageProfile
	if err := json.Unmarshal([]byte(body), &sp); err != nil {
		return false, nil
	}
	if sp.OSDisk.Caching == "" && len(sp.DataDisks) == 0 {
		return false, nil // not a storageProfile object — treat as unread
	}
	disks = append(disks, models.AzureDisk{
		Name: sp.OSDisk.Name, IsOS: true, Caching: sp.OSDisk.Caching,
	})
	for _, d := range sp.DataDisks {
		lun, _ := strconv.Atoi(d.Lun)
		if lun < 0 {
			lun = 0 // a LUN is a non-negative index; clamp garbage/hostile values
		}
		disks = append(disks, models.AzureDisk{
			Name: d.Name, IsOS: false, Lun: lun, Caching: d.Caching,
		})
	}
	return true, disks
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
		low := strings.ToLower(body)
		if strings.Contains(low, "ptp_hyperv") || strings.Contains(low, "refclock phc") {
			return true, true
		}
	}
	return checked, false
}
