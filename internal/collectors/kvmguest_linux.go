//go:build linux

package collectors

import (
	"context"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// KVMGuestCollector reports guest-side health for a Linux VM under QEMU/KVM
// (Proxmox/oVirt/libvirt). The KVM analog of VMwareCollector. Gated on
// KVMGuestAvailable() so it is silent and zero-cost on every non-KVM-guest host.
type KVMGuestCollector struct{}

func NewKVMGuestCollector() *KVMGuestCollector { return &KVMGuestCollector{} }

func (c *KVMGuestCollector) Name() string           { return "KVMGuest" }
func (c *KVMGuestCollector) Timeout() time.Duration { return 5 * time.Second }

// KVMGuestAvailable reports whether this host is a Linux guest under QEMU/KVM.
// DMI sys_vendor is "QEMU" on Proxmox / plain libvirt / oVirt; some RHV guests
// instead carry "KVM" in product_name. Cloud KVM guests report a cloud vendor
// (Amazon EC2 / Google / Microsoft), so this does NOT fire there — they have their
// own collectors. File-based (no exec) so it's cheap and replay-faithful.
func KVMGuestAvailable() bool {
	return isKVMGuest(
		readFileTrimmedLocal(filepath.Join(dmiIDDir, "sys_vendor")),
		readFileTrimmedLocal(filepath.Join(dmiIDDir, "product_name")),
	)
}

// isKVMGuest matches QEMU/KVM's DMI signatures while excluding the big clouds
// (whose vendors are "Amazon EC2"/"Google"/"Microsoft Corporation") and VMware.
func isKVMGuest(sysVendor, productName string) bool {
	if strings.Contains(strings.ToUpper(sysVendor), "QEMU") {
		return true
	}
	return strings.Contains(strings.ToUpper(productName), "KVM")
}

func (c *KVMGuestCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.KVMGuestInfo{
		IsGuest:     true,
		ProductName: readFileTrimmedLocal(filepath.Join(dmiIDDir, "product_name")),
	}

	// qemu-guest-agent — split into the host-added channel vs the guest-owned
	// binary/service so the verdict can tell "host never enabled it" from "you
	// haven't installed/started it".
	info.QGAChannelPresent = fileExists("/dev/virtio-ports/org.qemu.guest_agent.0")
	info.QGAInstalled = fileExists("/usr/sbin/qemu-ga") || fileExists("/usr/bin/qemu-ga")
	info.QGARunning = kvmQGARunning(ctx)

	// NIC drivers — reuse the shared sysfs walk, classify emulated with the KVM set.
	// internal-analysis-05-04: collectNICDrivers/collectKVMDiskBuses silently
	// skip unreadable entries and return (nil, nil) on a total enumeration
	// failure — the same shape as a guest with zero interfaces/disks, which
	// checkKVMGuest would otherwise report as confirmed-fully-paravirtual.
	// A direct readDirEntries check here (independent of collectNICDrivers's
	// internals) records whether enumeration was even attempted successfully.
	_, dirErr := readDirEntries("/sys/class/net")
	info.NICDriversChecked = dirErr == nil
	drivers, _ := collectNICDrivers("/sys/class/net")
	info.NICDrivers = drivers
	for iface, drv := range drivers {
		if kvmNICEmulated(drv) {
			info.EmulatedNICs = append(info.EmulatedNICs, iface)
		}
	}
	sort.Strings(info.EmulatedNICs)

	_, blockDirErr := readDirEntries("/sys/block")
	info.DiskBusesChecked = blockDirErr == nil
	info.DiskBuses, info.EmulatedDisks = collectKVMDiskBuses("/sys/block")

	info.BalloonLoaded = kernelModulePresent(readFileTrimmedLocal("/proc/modules"), "virtio_balloon")
	info.Clocksource = readFileTrimmedLocal("/sys/devices/system/clocksource/clocksource0/current_clocksource")
	info.StealPct = cumulativeStealPct(readFileTrimmedLocal("/proc/stat"))

	return info, nil
}

// kvmQGARunning reports whether the qemu-guest-agent is alive. Scans /proc for the
// qemu-ga process (distro-agnostic, no root); falls back to systemd only if /proc
// was unreadable. NOTE: do NOT use LookPath — qemu-ga lives in /usr/sbin, which is
// absent from a non-root PATH (verified live: LookPath missed a running agent).
func kvmQGARunning(ctx context.Context) bool {
	if running, ok := procCommRunning("qemu-ga"); ok {
		return running
	}
	if out, err := runCmd(ctx, "systemctl", "is-active", "qemu-guest-agent"); err == nil &&
		strings.TrimSpace(out) == "active" {
		return true
	}
	return false
}

// kvmNICEmulated reports whether a NIC driver is an emulated QEMU device (vs the
// paravirtual virtio_net). Emulated NICs work but burn host CPU and cap throughput.
// Explicit emulated set; virtio_net and SR-IOV passthrough VFs are NOT emulated.
func kvmNICEmulated(driver string) bool {
	switch strings.ToLower(driver) {
	case "e1000", "e1000e", "rtl8139", "8139cp", "8139too", "ne2k_pci", "pcnet32", "vlance":
		return true
	default:
		return false
	}
}

// collectKVMDiskBuses classifies each block device's bus as paravirtual
// (virtio-blk / virtio-scsi) or emulated (ide / sata / legacy LSI scsi), returning
// the bus map and the emulated subset. Emulated disk buses are the single most
// common cause of a slow Proxmox guest.
func collectKVMDiskBuses(blockDir string) (map[string]string, []string) {
	entries, err := readDirEntries(blockDir)
	if err != nil {
		return nil, nil
	}
	buses := map[string]string{}
	var emulated []string
	for _, e := range entries {
		dev := e.Name()
		bus := kvmDiskBus(dev, blockDir)
		if bus == "" {
			continue // cdrom/loop/dm/nvme — not a guest disk-bus concern
		}
		buses[dev] = bus
		if bus == "ide" || bus == "sata" || bus == "scsi" {
			emulated = append(emulated, dev)
		}
	}
	if len(buses) == 0 {
		return nil, nil
	}
	sort.Strings(emulated)
	return buses, buses2emptyNil(emulated)
}

func buses2emptyNil(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// kvmDiskBus classifies one block device's bus. vdX is virtio-blk; hdX is IDE; for
// sdX the controller is read from the sysfs path (virtio-scsi disks sit under a
// virtioN node, emulated SATA under an ataN node, legacy LSI SCSI under neither).
// Verified live: a Proxmox virtio-scsi disk resolves to ".../virtio1/host0/.../sda".
func kvmDiskBus(dev, blockDir string) string {
	switch {
	case strings.HasPrefix(dev, "vd"):
		return "virtio-blk"
	case strings.HasPrefix(dev, "hd"):
		return "ide"
	case strings.HasPrefix(dev, "sd"):
		link, err := readLink(filepath.Join(blockDir, dev))
		if err != nil {
			return "scsi" // controller unknown — treat as emulated SCSI, not silently OK
		}
		switch {
		case strings.Contains(link, "virtio"):
			return "virtio-scsi"
		case strings.Contains(link, "/ata"):
			return "sata"
		default:
			return "scsi" // LSI/megasas emulated SCSI
		}
	default:
		return ""
	}
}

// cumulativeStealPct returns CPU steal as a percentage of total CPU time since
// boot, parsed from the aggregate "cpu " line of /proc/stat (field 8 = steal).
// Since-boot ratio = a chronic-overcommit signal; 0 on any parse failure.
func cumulativeStealPct(procStat string) float64 {
	for _, line := range strings.Split(procStat, "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue // skip per-core "cpu0"/"cpu1" lines; want the aggregate
		}
		fields := strings.Fields(line) // cpu user nice system idle iowait irq softirq steal ...
		if len(fields) < 9 {
			return 0
		}
		var total, steal uint64
		for i := 1; i < len(fields); i++ {
			v, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				continue
			}
			total += v
			if i == 8 {
				steal = v
			}
		}
		if total == 0 {
			return 0
		}
		return float64(steal) / float64(total) * 100
	}
	return 0
}
