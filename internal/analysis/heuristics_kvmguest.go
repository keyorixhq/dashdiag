package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// kvmGuestStealWarnPct is the since-boot cumulative CPU-steal ratio at/above which
// we flag chronic host overcommit. Conservative — a lifetime average this high is
// unambiguous; the CPU collector reports the point-in-time rate separately, so this
// doesn't double-alarm on a transient spike.
const kvmGuestStealWarnPct = 10.0

// KVMGuestInsights is the exported entry point for `dsd kvm-guest`. It returns
// exactly what `dsd health` evaluates for a KVM/Proxmox guest (it IS checkKVMGuest),
// so the standalone verdict can't drift from health (cmd↔health consistency).
func KVMGuestInsights(v models.KVMGuestInfo) []models.Insight {
	return AdaptHostHints(checkKVMGuest(v))
}

// checkKVMGuest reports guest-side configuration health for a Linux VM under
// QEMU/KVM (Proxmox/oVirt/libvirt). The KVM analog of checkVMware: things a tenant
// can fix inside their own VM (guest agent, paravirtual NIC/disk drivers) plus
// host-imposed pressure that is evidence for whoever runs the hypervisor (CPU
// steal). Silent on every non-KVM-guest host (the collector is DMI-gated).
func checkKVMGuest(v models.KVMGuestInfo) []models.Insight {
	if !v.IsGuest {
		return nil
	}
	var out []models.Insight

	out = append(out, kvmguestQGAInsight(v)...)

	if len(v.EmulatedNICs) > 0 {
		out = append(out, insight("WARN", "KVMGuest",
			fmt.Sprintf("NIC(s) on an emulated driver (%s) — switch to VirtIO (virtio-net) for higher throughput at lower host CPU",
				kvmguestNICDescs(v)),
			[]string{"to fix: set the VM's network device model to VirtIO in the hypervisor (Proxmox: VM → Hardware → Network Device), then reboot"}))
	}

	if len(v.EmulatedDisks) > 0 {
		out = append(out, insight("WARN", "KVMGuest",
			fmt.Sprintf("disk(s) on an emulated bus (%s) — switch to VirtIO Block or VirtIO SCSI; emulated IDE/SATA is the most common cause of a slow Proxmox guest",
				kvmguestDiskDescs(v)),
			[]string{
				"to fix: detach the disk and re-add it as VirtIO Block / SCSI (with a VirtIO SCSI controller) in the hypervisor, then reboot",
				"note: changing the boot disk's bus may need the bootloader/initramfs to include virtio_blk/virtio_scsi",
			}))
	}

	if v.Clocksource != "" && v.Clocksource != "kvm-clock" {
		out = append(out, insight("INFO", "KVMGuest",
			fmt.Sprintf("clocksource is %q, not kvm-clock — kvm-clock is the low-overhead paravirtual clock for KVM guests", v.Clocksource),
			[]string{"to inspect: cat /sys/devices/system/clocksource/clocksource0/available_clocksource"}))
	}

	out = append(out, kvmguestStealInsight(v)...)

	// internal-analysis-05-04: an empty EmulatedNICs/EmulatedDisks only proves
	// "fully paravirtual" when the underlying sysfs enumeration actually
	// succeeded — if /sys/class/net or /sys/block itself couldn't be read,
	// EmulatedNICs/EmulatedDisks stay empty for the exact same reason a
	// genuinely healthy guest does, and the "all clean" recognition line
	// below would otherwise claim a paravirtual path that was never verified.
	if len(out) == 0 && (!v.NICDriversChecked || !v.DiskBusesChecked) {
		var unread []string
		if !v.NICDriversChecked {
			unread = append(unread, "NIC drivers (/sys/class/net)")
		}
		if !v.DiskBusesChecked {
			unread = append(unread, "disk buses (/sys/block)")
		}
		return append(out, unverifiedInsight("INFO", "KVMGuest",
			fmt.Sprintf("QEMU/KVM guest (%s) — could not verify paravirtual NIC/disk drivers: %s unreadable",
				kvmguestProductName(v), strings.Join(unread, ", ")),
			nil))
	}

	// All clean → one recognition line so the operator sees dsd identified the
	// platform and verified the paravirtual path (matches the VMware collector).
	if len(out) == 0 {
		out = append(out, insight("INFO", "KVMGuest",
			fmt.Sprintf("QEMU/KVM guest (%s) — paravirtual NIC+disk in use, qemu-guest-agent running, clocksource %s",
				kvmguestProductName(v), kvmguestOrUnknown(v.Clocksource)),
			nil))
	}
	return out
}

// kvmguestQGAInsight classifies the qemu-guest-agent state. The channel is added
// host-side (Proxmox VM option); the binary+service is the guest's to run — so a
// missing channel is HOST-side evidence (INFO), while a present channel with no
// running agent is the GUEST's to fix (WARN).
func kvmguestQGAInsight(v models.KVMGuestInfo) []models.Insight {
	if !v.QGAChannelPresent {
		return []models.Insight{insight("INFO", "KVMGuest",
			"no QEMU guest-agent channel — the host has not enabled the guest-agent device for this VM, so consistent (fs-frozen) backups and graceful shutdown are unavailable",
			[]string{
				"this is a host-side setting — Proxmox: VM → Options → QEMU Guest Agent → Enabled, then power-cycle the VM",
				"ask whoever runs the hypervisor to enable it if you need application-consistent backups",
			})}
	}
	if v.QGAInstalled && v.QGARunning {
		return nil // working
	}
	reason := "not installed"
	if v.QGAInstalled {
		reason = "installed but not running"
	}
	return []models.Insight{insight("WARN", "KVMGuest",
		fmt.Sprintf("qemu-guest-agent %s — the host offers the agent channel but the guest isn't answering: backups will be crash-consistent only and the host can't gracefully shut this VM down", reason),
		[]string{
			"to fix (Debian/Ubuntu): apt install qemu-guest-agent && systemctl enable --now qemu-guest-agent",
			"to fix (RHEL/SUSE):     dnf/zypper install qemu-guest-agent && systemctl enable --now qemu-guest-agent",
		})}
}

// kvmguestStealInsight flags chronic host overcommit from the since-boot steal
// ratio. Framed as host-side evidence, not a guest fault — the whole point of the
// guest-vs-provider split.
func kvmguestStealInsight(v models.KVMGuestInfo) []models.Insight {
	if v.StealPct < kvmGuestStealWarnPct {
		return nil
	}
	return []models.Insight{insight("WARN", "KVMGuest",
		fmt.Sprintf("CPU steal is %.1f%% since boot — the hypervisor is taking CPU from this guest (the host is overcommitted). This is host-side, not a guest fault.", v.StealPct),
		[]string{
			"evidence for whoever runs the hypervisor: the node has more vCPUs allocated than it can deliver",
			"to corroborate live: dsd cpu   (point-in-time steal rate)",
		})}
}

func kvmguestNICDescs(v models.KVMGuestInfo) string {
	descs := make([]string, 0, len(v.EmulatedNICs))
	for _, iface := range v.EmulatedNICs {
		if drv := v.NICDrivers[iface]; drv != "" {
			descs = append(descs, fmt.Sprintf("%s (%s)", iface, drv))
		} else {
			descs = append(descs, iface)
		}
	}
	return strings.Join(descs, ", ")
}

func kvmguestDiskDescs(v models.KVMGuestInfo) string {
	descs := make([]string, 0, len(v.EmulatedDisks))
	for _, dev := range v.EmulatedDisks {
		if bus := v.DiskBuses[dev]; bus != "" {
			descs = append(descs, fmt.Sprintf("%s (%s)", dev, bus))
		} else {
			descs = append(descs, dev)
		}
	}
	return strings.Join(descs, ", ")
}

func kvmguestProductName(v models.KVMGuestInfo) string {
	if v.ProductName == "" {
		return "QEMU"
	}
	return v.ProductName
}

func kvmguestOrUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
