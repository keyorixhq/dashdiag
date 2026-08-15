package models

// KVMGuestInfo reports guest-side health for a Linux VM running under QEMU/KVM
// (Proxmox VE, oVirt/RHV, plain libvirt). Populated only when the DMI vendor is
// QEMU (gate: KVMGuestAvailable); nil/zero on every other host so it adds no noise.
//
// This is the KVM/Proxmox analog of VMwareInfo, with the same guest-vs-host
// framing: what a tenant can fix inside their own VM (guest agent, paravirtual
// drivers) vs. host-imposed pressure that is evidence for whoever runs the
// hypervisor (CPU steal, ballooning). Built for the case the node-side `dsd pve`
// does NOT cover: someone handed a VM on someone else's Proxmox with no console
// access.
//
// Cloud KVM guests (AWS Nitro / GCP / Azure) report a cloud DMI vendor — "Amazon
// EC2", "Google", "Microsoft" — not "QEMU", and have their own collectors, so they
// do not double up here.
type KVMGuestInfo struct {
	IsGuest     bool   `json:"is_guest"`
	ProductName string `json:"product_name,omitempty"` // DMI product_name, e.g. "Standard PC (i440FX + PIIX, 1996)"

	// qemu-guest-agent — the host talks to the guest over a virtio-serial channel
	// (/dev/virtio-ports/org.qemu.guest_agent.0) to do fs-freeze (consistent
	// backups), graceful shutdown, and IP reporting. Without it, Proxmox backups are
	// crash-consistent only and the host can't cleanly shut the guest down. The
	// channel is added host-side (Proxmox "QEMU Guest Agent" option); the agent
	// binary+service is the guest's responsibility — so the three signals are split.
	QGAChannelPresent bool `json:"qga_channel_present"` // host added the agent device
	QGAInstalled      bool `json:"qga_installed"`       // qemu-ga binary present (sbin-safe, not LookPath)
	QGARunning        bool `json:"qga_running"`         // qemu-guest-agent service active

	// Paravirtual vs emulated NICs. Emulated (e1000/e1000e/rtl8139/pcnet) burn host
	// CPU and cap throughput versus virtio-net.
	NICDrivers   map[string]string `json:"nic_drivers,omitempty"`   // iface -> driver
	EmulatedNICs []string          `json:"emulated_nics,omitempty"` // ifaces on emulated drivers
	// NICDriversChecked is false when /sys/class/net itself couldn't be
	// enumerated — distinct from a genuine empty NICDrivers (no interfaces
	// found), which checkKVMGuest would otherwise read identically as
	// "confirmed fully paravirtual".
	NICDriversChecked bool `json:"nic_drivers_checked,omitempty"`

	// Disk bus per block device. Paravirtual virtio-blk (vdX) / virtio-scsi are
	// fast; emulated IDE/SATA (and legacy LSI SCSI) are slow — the single most common
	// "why is my Proxmox VM slow" cause.
	DiskBuses     map[string]string `json:"disk_buses,omitempty"`     // dev -> virtio-blk|virtio-scsi|sata|ide|scsi
	EmulatedDisks []string          `json:"emulated_disks,omitempty"` // disks on an emulated bus
	// DiskBusesChecked is false when /sys/block itself couldn't be
	// enumerated — see NICDriversChecked.
	DiskBusesChecked bool `json:"disk_buses_checked,omitempty"`

	BalloonLoaded bool   `json:"balloon_loaded"`        // virtio_balloon present (host can reclaim memory)
	Clocksource   string `json:"clocksource,omitempty"` // current_clocksource ("kvm-clock" is the paravirtual one)

	// Host-side pressure: cumulative CPU steal since boot (the hypervisor took the
	// CPU from this guest). The since-boot ratio is a chronic-overcommit signal — the
	// CPU collector reports the point-in-time rate separately, so this is framed as
	// provider evidence, not a duplicate live alarm.
	StealPct float64 `json:"steal_pct"`
}
