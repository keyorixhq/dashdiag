package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkVMware reports guest-side configuration health for a Linux VMware guest:
// open-vm-tools presence/state and paravirtual NIC drivers. Silent on every
// non-VMware host (the collector only runs behind the DMI gate). When everything
// is in order it emits a single INFO line so the operator can see dsd recognised
// the platform — useful on a VMware estate where that recognition builds trust.
func checkVMware(v models.VMwareInfo) []models.Insight {
	if !v.IsGuest {
		return nil
	}
	name := v.ProductName
	if name == "" {
		name = "VMware"
	}
	var out []models.Insight

	switch {
	case !v.ToolsInstalled:
		out = append(out, insight("WARN", "VMware",
			"open-vm-tools not installed on this VMware guest — no time sync, quiesced backups, graceful shutdown, or memory ballooning",
			[]string{"to fix: apt install open-vm-tools   (RHEL/SUSE: dnf/zypper install open-vm-tools)"}))
	case !v.ToolsRunning:
		out = append(out, insight("WARN", "VMware",
			"open-vm-tools installed but not running — quiesced snapshots/backups and graceful guest shutdown will fail",
			[]string{"to fix: systemctl enable --now vmtoolsd   (some distros: open-vm-tools)"}))
	}

	if len(v.EmulatedNICs) > 0 {
		out = append(out, insight("WARN", "VMware",
			fmt.Sprintf("NIC(s) on an emulated driver (%s) — vmxnet3 (paravirtual) gives higher throughput at lower host CPU",
				strings.Join(emulatedNICDescs(v), ", ")),
			[]string{"to fix: set the VM's network adapter type to VMXNET 3 in vSphere, then reboot the guest"}))
	}

	out = append(out, vmwareResourceConstraints(v)...)
	out = append(out, vmwareSCSITimeoutCheck(v)...)
	out = append(out, vmwareEnableUUIDCheck(v)...)
	out = append(out, vmwareVMXNETCheck(v)...)

	// open-vm-tools is running but the resource-pressure stat interface did not
	// answer (old tools / no permission / stat absent), so vmwareResourceConstraints
	// read nothing. Don't let the all-clean INFO below imply ballooning/host-swap/
	// host caps were verified — surface that they could NOT be checked.
	if v.ToolsRunning && !v.StatAvailable {
		out = append(out, insight("INFO", "VMware",
			"VMware resource-pressure stats unavailable (vmware-toolbox-cmd stat failed) — ballooning / host-swap / host caps NOT verified",
			[]string{
				"to inspect: vmware-toolbox-cmd stat balloon",
				"note: requires a recent open-vm-tools with the stat interface",
			}))
	}

	// All guest-side checks clean → one INFO context line confirming recognition,
	// enriched with the paravirtual-driver state so the operator sees dsd's full
	// VMware-guest read at a glance (no WARN — these are informational facts).
	if len(out) == 0 {
		out = append(out, insight("INFO", "VMware",
			fmt.Sprintf("VMware guest (%s) — open-vm-tools running; NICs: %s; paravirtual SCSI: %s; balloon: %s",
				name, vmwareNICSummary(v), vmwareYesNo(v.PVSCSILoaded), vmwareYesNo(v.BalloonLoaded)),
			nil))
	}
	return out
}

// vmwareResourceConstraints reports host-imposed memory/CPU pressure visible
// from inside the guest via open-vm-tools stat counters: active ballooning,
// host-swapped guest memory, and explicit CPU/memory caps. These are the
// memory/CPU analog of CPU steal — strong guest-side evidence that a "slow VM"
// is the host's doing, which exonerates the guest.
func vmwareResourceConstraints(v models.VMwareInfo) []models.Insight {
	if !v.StatAvailable {
		return nil
	}
	var out []models.Insight
	if v.BalloonMB > 0 {
		out = append(out, insight("WARN", "VMware",
			fmt.Sprintf("host is reclaiming %d MB of this guest's RAM via the balloon driver — the ESXi host is under memory pressure", v.BalloonMB),
			[]string{
				"this is host-side memory pressure, not a guest fault",
				"to inspect: vmware-toolbox-cmd stat balloon",
				"note: sustained ballooning means the host is overcommitted — raise the VM's memory reservation or rebalance the host",
			}))
	}
	if v.HostSwapMB > 0 {
		out = append(out, insight("WARN", "VMware",
			fmt.Sprintf("host has swapped %d MB of this guest's memory to disk — severe host memory pressure (hypervisor-level swap is far slower than guest swap)", v.HostSwapMB),
			[]string{
				"this is host-side memory pressure, not a guest fault",
				"to inspect: vmware-toolbox-cmd stat swap",
				"note: host swapping causes large, unpredictable latency spikes inside the guest",
			}))
	}
	if v.MemLimitMB > 0 {
		if binding, known := vmwareMemLimitBinding(v); known && !binding {
			out = append(out, insight("INFO", "VMware",
				fmt.Sprintf("a host memory limit of %d MB is configured but it is at/above this VM's RAM (%d MB), so it is currently non-binding", v.MemLimitMB, v.TotalRAMMB),
				[]string{"note: it would only cause ballooning/swap if this VM's RAM were raised above the limit"}))
		} else {
			out = append(out, insight("WARN", "VMware",
				fmt.Sprintf("a host-imposed memory limit of %d MB is set on this VM — RAM above the limit is ballooned/swapped even when the host has free memory", v.MemLimitMB),
				[]string{
					"to inspect: vmware-toolbox-cmd stat memlimit",
					"note: a memory limit below the configured RAM is a common, invisible cause of guest paging — remove it in vSphere unless intentional",
				}))
		}
	}
	if v.CPULimitMHz > 0 {
		if binding, known := vmwareCPULimitBinding(v); known && !binding {
			out = append(out, insight("INFO", "VMware",
				fmt.Sprintf("a host CPU limit of %d MHz is configured but it is at/above this VM's capacity (%d vCPU × %d MHz), so it is currently non-binding", v.CPULimitMHz, v.NumVCPU, v.HostMHzPerCPU),
				[]string{"note: it would only throttle the guest if the limit were lowered below capacity, or capacity raised above it — watch CPU steal"}))
		} else {
			out = append(out, insight("WARN", "VMware",
				fmt.Sprintf("a host-imposed CPU limit of %d MHz is set on this VM — the guest is throttled below its vCPU capacity regardless of host load", v.CPULimitMHz),
				[]string{
					"to inspect: vmware-toolbox-cmd stat cpulimit",
					"note: a CPU limit is an invisible cause of guest slowness — remove it in vSphere unless intentional",
				}))
		}
	}
	return out
}

// vmwareMemLimitBinding reports whether a configured memory limit can actually
// bite — it must sit below the guest's RAM, else the VM can never reach it. A 2%
// margin absorbs reporting rounding. known=false means RAM is unknown, so the
// caller keeps the conservative WARN rather than hiding a possibly-real limit.
func vmwareMemLimitBinding(v models.VMwareInfo) (binding, known bool) {
	if v.TotalRAMMB <= 0 {
		return false, false
	}
	return v.MemLimitMB < int(float64(v.TotalRAMMB)*0.98), true
}

// vmwareCPULimitBinding reports whether a configured CPU limit can actually bite —
// it must sit below the VM's capacity (vCPUs × per-vCPU host clock). 2% margin for
// rounding. known=false (capacity unknown) → caller keeps the WARN.
func vmwareCPULimitBinding(v models.VMwareInfo) (binding, known bool) {
	capacity := v.NumVCPU * v.HostMHzPerCPU
	if capacity <= 0 {
		return false, false
	}
	return v.CPULimitMHz < int(float64(capacity)*0.98), true
}

// vmwareSCSITimeoutCheck flags SCSI disks whose command timeout is below
// VMware's recommended 180s. The kernel default (30s) risks the guest
// filesystem going read-only during a vMotion / storage-failover stun.
func vmwareSCSITimeoutCheck(v models.VMwareInfo) []models.Insight {
	if len(v.LowSCSITimeouts) == 0 {
		return nil
	}
	descs := make([]string, 0, len(v.LowSCSITimeouts))
	for _, dev := range v.LowSCSITimeouts {
		descs = append(descs, fmt.Sprintf("%s (%ds)", dev, v.SCSITimeouts[dev]))
	}
	return []models.Insight{insight("WARN", "VMware",
		fmt.Sprintf("SCSI disk command timeout below VMware's recommended 180s (%s) — the guest filesystem may go read-only during a vMotion or storage failover",
			strings.Join(descs, ", ")),
		[]string{
			"to fix now: echo 180 > /sys/block/sdX/device/timeout   (per disk, non-persistent)",
			"to persist: install open-vm-tools (ships a udev rule) or add a udev rule setting timeout=180",
		})}
}

// vmwareEnableUUIDCheck flags SCSI disks that expose no stable hardware ID — the
// signature of disk.EnableUUID=FALSE on a vSphere VM. Without page 0x83, the
// disks have no /dev/disk/by-id serial, so the vSphere CSI driver and by-id
// device naming cannot identify them and k8s persistent volumes can mis-bind.
// Silent when no SCSI disks were examined (e.g. an NVMe-only guest) or when all
// of them carry an ID.
func vmwareEnableUUIDCheck(v models.VMwareInfo) []models.Insight {
	if !v.SCSIDisksChecked || len(v.DisksNoStableID) == 0 {
		return nil
	}
	return []models.Insight{insight("WARN", "VMware",
		fmt.Sprintf("disk.EnableUUID appears disabled — SCSI disk(s) %s expose no stable hardware ID (no SCSI page 0x83), so /dev/disk/by-id naming and the vSphere CSI driver cannot identify them; k8s persistent volumes can mis-bind",
			strings.Join(v.DisksNoStableID, ", ")),
		[]string{
			"to fix: set disk.EnableUUID = TRUE in the VM's Advanced Configuration (vSphere), then reboot the guest",
			"note: required for the vSphere CSI driver and stable by-id device naming; the VM default is often off",
		})}
}

// vmwareVMXNETCheck flags vmxnet3 NICs whose driver-internal counters show the
// rings are undersized for the traffic: RX buffer-allocation failures, RX ring
// out-of-buffer, or TX ring exhaustion. Rate-gated (nicErrorRateHigh: an absolute
// floor AND a fraction of total packets) so a flat cumulative count on a
// long-uptime host doesn't false-WARN. These counters are vmxnet3-specific and
// not covered by the generic Network collector's rx/tx_errors/dropped check.
func vmwareVMXNETCheck(v models.VMwareInfo) []models.Insight {
	var out []models.Insight
	for _, s := range v.VMXNETStats {
		var reasons []string
		if nicErrorRateHigh(s.RxBufAllocFail, s.RxPackets) {
			reasons = append(reasons, fmt.Sprintf("RX buffer-allocation failures (%d)", s.RxBufAllocFail))
		}
		if nicErrorRateHigh(s.RxOOB, s.RxPackets) {
			reasons = append(reasons, fmt.Sprintf("RX ring out-of-buffer (%d)", s.RxOOB))
		}
		if nicErrorRateHigh(s.TxRingFull, s.TxPackets) {
			reasons = append(reasons, fmt.Sprintf("TX ring exhaustion (%d)", s.TxRingFull))
		}
		if len(reasons) == 0 {
			continue
		}
		out = append(out, insight("WARN", "VMware",
			fmt.Sprintf("vmxnet3 %s: %s — the driver rings are undersized for the traffic and packets are being dropped",
				s.Iface, strings.Join(reasons, ", ")),
			[]string{
				fmt.Sprintf("to inspect: ethtool -S %s | grep -E 'buf alloc fail|ring full|rx OOB'", s.Iface),
				fmt.Sprintf("to fix: raise the ring size — ethtool -G %s rx 4096 tx 4096 (cap shown by ethtool -g %s)", s.Iface, s.Iface),
			}))
	}
	return out
}

// vmwareNICSummary lists the distinct NIC drivers in use (e.g. "vmxnet3") for
// the recognition line; "none detected" when no NICs were read.
func vmwareNICSummary(v models.VMwareInfo) string {
	if len(v.NICDrivers) == 0 {
		return "none detected"
	}
	seen := map[string]bool{}
	drivers := make([]string, 0, len(v.NICDrivers))
	for _, drv := range v.NICDrivers {
		if !seen[drv] {
			seen[drv] = true
			drivers = append(drivers, drv)
		}
	}
	sort.Strings(drivers)
	return strings.Join(drivers, ", ")
}

func vmwareYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// emulatedNICDescs renders "iface (driver)" for each emulated NIC, e.g.
// "ens160 (e1000)", so the operator sees both the interface and the driver.
func emulatedNICDescs(v models.VMwareInfo) []string {
	descs := make([]string, 0, len(v.EmulatedNICs))
	for _, iface := range v.EmulatedNICs {
		if drv := v.NICDrivers[iface]; drv != "" {
			descs = append(descs, fmt.Sprintf("%s (%s)", iface, drv))
		} else {
			descs = append(descs, iface)
		}
	}
	return descs
}
