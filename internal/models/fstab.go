package models

// FstabInfo reports /etc/fstab entries whose UUID=/PARTUUID= reference matches no
// present block device — the cloned-VM / replaced-disk failure where fstab still
// names an old filesystem id, so the mount fails at boot (and a root/boot mount
// drops the host to an emergency shell). Checked is false when verification wasn't
// possible (no /etc/fstab, or /dev/disk/by-uuid + by-partuuid both absent).
type FstabInfo struct {
	Checked bool         `json:"checked"`
	Drifts  []FstabDrift `json:"drifts,omitempty"`
}

// FstabDrift is one fstab entry whose tag reference has no matching device.
type FstabDrift struct {
	Spec       string `json:"spec"`        // the fstab fsspec, e.g. "UUID=abc-123"
	MountPoint string `json:"mount_point"` // e.g. "/data"
	BootMount  bool   `json:"boot_mount"`  // / or /boot* — a drift here blocks boot
}
