//go:build linux

package collectors

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// KVMCollector gathers KVM/libvirt diagnostics via virsh shell-outs.
// Gate: libvirtd must be running (checked via virsh version exit code).
// Linux only — libvirt is not available on other platforms.
type KVMCollector struct {
	Deep bool
}

func NewKVMCollector() *KVMCollector     { return &KVMCollector{} }
func NewKVMDeepCollector() *KVMCollector { return &KVMCollector{Deep: true} }

func (c *KVMCollector) Name() string           { return "KVM" }
func (c *KVMCollector) Timeout() time.Duration { return 15 * time.Second }

// pveQEMUDir holds one <vmid>.pid file per running Proxmox VE QEMU guest.
// Proxmox manages QEMU directly (no libvirt), so virsh sees nothing.
const pveQEMUDir = "/var/run/qemu-server"

func (c *KVMCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.KVMInfo{}

	// Gate: virsh version proves libvirtd is reachable
	verOut, err := runCmd(ctx, "virsh", "version", "--daemon")
	if err != nil {
		// libvirt not installed or daemon not running. On Proxmox VE, QEMU is
		// managed directly via /var/run/qemu-server/*.pid — enumerate from there
		// instead of returning empty (see BUG-015).
		if IsPVEHost() {
			kvmCollectPVEFromDir(pveQEMUDir, info)
		}
		return info, nil
	}
	info.Detected = true
	parseVirshVersion(verOut, info)

	// Collect in parallel-ish order (sequential is fine — each call is fast)
	kvmCollectVMs(ctx, info, c.Deep)
	kvmCollectNetworks(ctx, info)
	kvmCollectPools(ctx, info)

	return info, nil
}

// parseVirshVersion extracts libvirt and QEMU versions from virsh version output.
func parseVirshVersion(out string, info *models.KVMInfo) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Using library:"):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				info.LibvirtVer = parts[len(parts)-1]
			}
		case strings.HasPrefix(line, "Running hypervisor:"):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				info.QEMUVer = parts[len(parts)-1]
			}
		}
	}
}

// ── VM collection ─────────────────────────────────────────────────────────────

func kvmCollectVMs(ctx context.Context, info *models.KVMInfo, deep bool) {
	out, err := runCmd(ctx, "virsh", "list", "--all", "--name")
	if err != nil {
		// libvirt was detected (virsh version --daemon succeeded) but enumeration
		// failed. Returning silently left VMs empty, which reads as "no VMs / healthy"
		// — so a crashed VM on a host whose `virsh list` is failing went unreported.
		// Record the failure so the verdict surfaces it instead of a green OK.
		info.Status = "enum-failed"
		info.StatusReason = "libvirt is up but `virsh list` failed — VM states could not be read"
		return
	}
	if strings.TrimSpace(out) == "" {
		return // genuinely no domains defined
	}

	for _, name := range strings.Split(strings.TrimSpace(out), "\n") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		// A domain name beginning with "-" would be parsed by virsh as an
		// option rather than the positional domain argument on every
		// downstream call (dominfo/dumpxml/domblkerror all take name as a
		// bare argv element, no shell involved) — silently reinterpreting
		// the subcommand instead of erroring. Skipping is a deliberate
		// trade: this one oddly-named domain goes unreported rather than
		// producing misleading results attributed to it.
		if strings.HasPrefix(name, "-") {
			continue
		}
		vm := kvmDomInfo(ctx, name)
		kvmCheckDiskErrors(ctx, &vm)
		kvmReadLastLogError(&vm)
		if deep {
			// dumpxml reads the persistent domain definition, so this works for
			// shut-off VMs too — the whole point of the originally-scoped "XML
			// config check for non-running VMs" (dsd kvm --deep).
			kvmCollectXMLDeep(ctx, &vm)
		}
		updateKVMCounts(info, &vm)
		info.VMs = append(info.VMs, vm)
	}
}

// kvmDomainXML is the minimal libvirt domain XML shape needed for the deep
// config check: disk bus/backing-file and NIC model.
type kvmDomainXML struct {
	Devices struct {
		Disks []struct {
			Device string `xml:"device,attr"` // "disk" vs "cdrom"/"floppy"
			Source struct {
				File string `xml:"file,attr"` // only set for plain file-backed disks
			} `xml:"source"`
			Target struct {
				Dev string `xml:"dev,attr"`
				Bus string `xml:"bus,attr"`
			} `xml:"target"`
		} `xml:"disk"`
		Interfaces []struct {
			Mac struct {
				Address string `xml:"address,attr"`
			} `xml:"mac"`
			Model struct {
				Type string `xml:"type,attr"`
			} `xml:"model"`
		} `xml:"interface"`
	} `xml:"devices"`
}

// kvmEmulatedNICModels/kvmEmulatedDiskBuses are explicit allowlists of known
// emulated (non-VirtIO) device models/buses. Explicit, not "anything that
// isn't virtio", so an unrecognized or future model/bus name is silently
// ignored rather than misclassified as emulated — the false-WARN guard.
var kvmEmulatedNICModels = map[string]bool{
	"e1000": true, "e1000e": true, "rtl8139": true, "pcnet": true, "ne2k_pci": true,
}

var kvmEmulatedDiskBuses = map[string]bool{"ide": true, "sata": true}

// kvmCollectXMLDeep parses `virsh dumpxml` for vm and fills its deep-only
// fields (emulated NIC/disk detection + missing backing-file detection).
// Silent on any read/parse failure — say nothing rather than guess.
func kvmCollectXMLDeep(ctx context.Context, vm *models.KVMVM) {
	out, err := runCmd(ctx, "virsh", "dumpxml", vm.Name)
	if err != nil {
		return
	}
	var dom kvmDomainXML
	if xml.Unmarshal([]byte(out), &dom) != nil {
		return
	}

	for _, ifc := range dom.Devices.Interfaces {
		if !kvmEmulatedNICModels[ifc.Model.Type] {
			continue
		}
		id := ifc.Mac.Address
		if id == "" {
			id = ifc.Model.Type
		}
		vm.EmulatedNICs = append(vm.EmulatedNICs, fmt.Sprintf("%s (%s)", id, ifc.Model.Type))
	}

	for _, disk := range dom.Devices.Disks {
		if disk.Device != "disk" {
			continue // cdrom/floppy — an emulated IDE/SATA bus there is normal
		}
		if kvmEmulatedDiskBuses[disk.Target.Bus] {
			vm.EmulatedDisks = append(vm.EmulatedDisks, fmt.Sprintf("%s (%s)", disk.Target.Dev, disk.Target.Bus))
		}
		// Missing backing file — only for plain file-backed disks. Network/block
		// sources (rbd, nbd, LVM) never populate Source.File, so they're silently
		// skipped rather than guessed at.
		if vm.MissingDiskPath == "" && disk.Source.File != "" && !fileExists(disk.Source.File) {
			vm.MissingDiskPath = disk.Source.File
		}
	}
}

// kvmDomInfo runs virsh dominfo for a single domain and parses it.
func kvmDomInfo(ctx context.Context, name string) models.KVMVM {
	vm := models.KVMVM{Name: name, ID: -1}
	out, err := runCmd(ctx, "virsh", "dominfo", name)
	if err != nil {
		return vm
	}
	for _, line := range strings.Split(out, "\n") {
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colonIdx])
		val := strings.TrimSpace(line[colonIdx+1:])
		switch key {
		case "Id":
			if val != "-" {
				vm.ID, _ = strconv.Atoi(val)
			}
		case "State":
			vm.State = models.KVMVMState(val)
		case "CPU(s)":
			vm.VCPU, _ = strconv.Atoi(val)
		case "Max memory":
			// "524288 KiB"
			fields := strings.Fields(val)
			if len(fields) >= 1 {
				kib, _ := strconv.Atoi(fields[0])
				vm.MaxMemMB = kib / 1024
			}
		case "Used memory":
			fields := strings.Fields(val)
			if len(fields) >= 1 {
				kib, _ := strconv.Atoi(fields[0])
				vm.UsedMemMB = kib / 1024
			}
		case "Autostart":
			vm.AutoStart = val == "enable"
		}
	}
	return vm
}

// kvmCheckDiskErrors runs virsh domblkerror. Any non-empty output other than the
// "No errors found" line indicates a live block-device I/O error.
func kvmCheckDiskErrors(ctx context.Context, vm *models.KVMVM) {
	if vm.ID < 0 {
		return // not running — no live disk stats
	}
	out, err := runCmd(ctx, "virsh", "domblkerror", vm.Name)
	if err != nil {
		return
	}
	// "No errors found" = clean. Actual errors look like: "vda  I/O error"
	lower := strings.ToLower(strings.TrimSpace(out))
	if lower != "" && !strings.Contains(lower, "no errors") {
		vm.DiskIOError = true
	}
}

// kvmReadLastLogError reads the last error line from /var/log/libvirt/qemu/<name>.log.
func kvmReadLastLogError(vm *models.KVMVM) {
	const logDir = "/var/log/libvirt/qemu"
	logPath := filepath.Join(logDir, vm.Name+".log")
	// vm.Name comes from `virsh list --all --name` with no character-class
	// validation — a domain name containing "../" segments would otherwise
	// let filepath.Join resolve outside logDir (e.g. to /var/log/auth.log),
	// reading an arbitrary .log-suffixed file the dsd process can access and
	// surfacing its content as this VM's LastLogError.
	if logPath != logDir && !strings.HasPrefix(logPath, logDir+string(filepath.Separator)) {
		return
	}
	f, err := openFile(logPath) // #nosec G304 -- logPath is confined to logDir by the HasPrefix check above
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck

	keywords := []string{"error", "failed", "killed", "abort", "permission denied", "no such file"}
	var lastError string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		lower := strings.ToLower(line)
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				lastError = strings.TrimSpace(line)
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return
	}
	if lastError != "" {
		vm.LastLogError = truncateRunes(lastError, 120)
	}
}

// updateKVMCounts increments the relevant summary counters.
func updateKVMCounts(info *models.KVMInfo, vm *models.KVMVM) {
	switch vm.State {
	case models.KVMRunning:
		info.VMsRunning++
	case models.KVMPaused:
		info.VMsPaused++
	case models.KVMCrashed:
		info.VMsCrashed++
	case models.KVMShutOff, models.KVMShutDown:
		if vm.AutoStart {
			info.VMsDownAutostart++
		}
	case models.KVMPMSuspended, models.KVMInShutdown, models.KVMIdle, models.KVMBlocked:
		info.VMsAbnormal++
	case "":
		// virsh dominfo failed (kvmDomInfo couldn't read State) — the domain is
		// defined but its state is unknown. Don't let it pass as healthy.
		info.VMsUnreadable++
	default:
		// A non-empty state string that matches none of the known constants — a
		// future libvirt/QEMU release introducing a new domain state, or a
		// modified/wrapped virsh on PATH. Count it the same as the unreadable
		// case rather than letting it silently vanish from every summary
		// counter, understating the true count of abnormal/crashed VMs.
		info.VMsUnreadable++
	}
	if vm.DiskIOError {
		info.DiskIOErrors++
	}
}

// ── Network collection ────────────────────────────────────────────────────────

func kvmCollectNetworks(ctx context.Context, info *models.KVMInfo) {
	out, err := runCmd(ctx, "virsh", "net-list", "--all")
	if err != nil {
		// internal-collectors-18-04: mirrors kvmCollectVMs' enum-failed guard —
		// returning silently left Networks empty and NetworksInactive at 0,
		// indistinguishable from a host with no libvirt networks defined at all.
		// Guarded on Status=="" so a VM enumeration failure (checked first, and
		// the more severe of the two) keeps its own reason rather than being
		// silently overwritten by this one.
		if info.Status == "" {
			info.Status = "enum-failed"
			info.StatusReason = "libvirt is up but `virsh net-list` failed — network states could not be read"
		}
		return
	}
	for _, line := range strings.Split(out, "\n") {
		// Format: " Name      State    Autostart   Persistent"
		// Data:   " default   active   yes         yes"
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] == "Name" || strings.HasPrefix(fields[0], "-") {
			continue
		}
		net := models.KVMNetwork{
			Name:      fields[0],
			State:     fields[1],
			Autostart: fields[2] == "yes",
		}
		if net.State != "active" {
			info.NetworksInactive++
		} else {
			// Check bridge link state
			bridgeOut, _ := runCmd(ctx, "virsh", "net-info", net.Name)
			net.Bridge = kvmParseBridge(bridgeOut)
			if net.Bridge != "" {
				linkOut, _ := runCmd(ctx, "ip", "link", "show", net.Bridge)
				net.BridgeUp = strings.Contains(linkOut, "state UP") ||
					(strings.Contains(linkOut, net.Bridge) && !strings.Contains(linkOut, "state DOWN"))
			}
		}
		info.Networks = append(info.Networks, net)
	}
}

// kvmParseBridge extracts the bridge name from virsh net-info output.
func kvmParseBridge(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Bridge:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}

// ── Storage pool collection ───────────────────────────────────────────────────

func kvmCollectPools(ctx context.Context, info *models.KVMInfo) {
	out, err := runCmd(ctx, "virsh", "pool-list", "--all")
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] == "Name" || strings.HasPrefix(fields[0], "-") {
			continue
		}
		pool := models.KVMStoragePool{
			Name:  fields[0],
			State: fields[1],
		}
		if pool.State != "active" {
			info.PoolsInactive++
			info.StoragePools = append(info.StoragePools, pool)
			continue
		}
		// Get capacity details via pool-info
		infoOut, err := runCmd(ctx, "virsh", "pool-info", pool.Name)
		if err == nil {
			kvmParsePoolInfo(infoOut, &pool)
		}
		if pool.CapacityGB > 0 && pool.UsedPct >= 85 {
			info.PoolsNearFull++
		}
		info.StoragePools = append(info.StoragePools, pool)
	}
}

// kvmParsePoolInfo extracts capacity from virsh pool-info output.
func kvmParsePoolInfo(out string, pool *models.KVMStoragePool) {
	for _, line := range strings.Split(out, "\n") {
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colonIdx])
		val := strings.TrimSpace(line[colonIdx+1:])
		switch key {
		case "Capacity":
			pool.CapacityGB = kvmParseBytes(val)
		case "Available":
			pool.AvailableGB = kvmParseBytes(val)
		}
	}
	if pool.CapacityGB > 0 {
		used := pool.CapacityGB - pool.AvailableGB
		pool.UsedPct = used / pool.CapacityGB * 100
	}
}

// kvmParseBytes converts virsh capacity strings like "200.00 GiB" to GB.
func kvmParseBytes(s string) float64 {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return 0
	}
	val := parseFloat(fields[0])
	unit := strings.ToUpper(fields[1])
	switch {
	case strings.HasPrefix(unit, "TIB") || strings.HasPrefix(unit, "TB"):
		return val * 1000
	case strings.HasPrefix(unit, "GIB") || strings.HasPrefix(unit, "GB"):
		return val
	case strings.HasPrefix(unit, "MIB") || strings.HasPrefix(unit, "MB"):
		return val / 1024
	case strings.HasPrefix(unit, "KIB") || strings.HasPrefix(unit, "KB"):
		return val / (1024 * 1024)
	}
	return 0
}

// KVMAvailable returns true when virsh is found, indicating libvirt is installed.
// The actual daemon check happens in Collect() — this is a cheap binary check.
// Fallback: Proxmox VE does not use libvirt — it manages QEMU directly, leaving
// a pid file per running VM in /var/run/qemu-server/ (see BUG-015).
// Called from buildHealthCollectors BEFORE any collector's Collect(ctx) runs
// (registration-time gate, same shape as MemcachedAvailable/K8sAvailable/
// TraefikAvailable/...) — there is no run-scoped context to propagate yet, so
// context.Background() here is the same established convention those other
// gate functions already use, not the re-created-context anti-pattern.
func KVMAvailable() bool {
	if _, err := runCmdTimeout(context.Background(), 2*time.Second, "virsh", "version", "--daemon"); err == nil {
		return true
	}
	return pveHasRunningQEMU()
}

// pveHasRunningQEMU reports whether any Proxmox VE QEMU guest is running, by
// the presence of at least one <vmid>.pid file in /var/run/qemu-server/.
func pveHasRunningQEMU() bool {
	matches, _ := glob(filepath.Join(pveQEMUDir, "*.pid"))
	return len(matches) > 0
}

// kvmCollectPVEFromDir enumerates Proxmox VE QEMU guests from the per-VM pid
// files Proxmox writes to dir (normally /var/run/qemu-server/<vmid>.pid).
// A guest counts as running when its pid file points to a live "kvm" process.
func kvmCollectPVEFromDir(dir string, info *models.KVMInfo) {
	matches, _ := glob(filepath.Join(dir, "*.pid"))
	if len(matches) == 0 {
		return
	}
	info.Detected = true
	for _, pidFile := range matches {
		vmid := strings.TrimSuffix(filepath.Base(pidFile), ".pid")
		vm := models.KVMVM{Name: "VM " + vmid, ID: -1, State: models.KVMShutOff}
		if pid, ok := readPVEVMPid(pidFile); ok && pveKVMProcessAlive(pid) {
			vm.ID = pid
			vm.State = models.KVMRunning
		}
		updateKVMCounts(info, &vm)
		info.VMs = append(info.VMs, vm)
	}
}

// readPVEVMPid reads a Proxmox <vmid>.pid file and returns the contained pid.
func readPVEVMPid(path string) (int, bool) {
	data, err := readFile(path) // #nosec G304 -- fixed /var/run/qemu-server path
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// pveKVMProcessAlive confirms pid maps to a live process whose name is "kvm",
// guarding against stale pid files and pid reuse.
func pveKVMProcessAlive(pid int) bool {
	data, err := readFile(filepath.Join("/proc", strconv.Itoa(pid), "status")) // #nosec G304
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Name:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Name:")) == "kvm"
		}
	}
	return false
}
