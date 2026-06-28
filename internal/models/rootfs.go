package models

// RootFSInfo reports an UNEXPECTED read-only root filesystem — `/` mounted ro on a
// normally-writable fs whose fstab intends it read-write, with no immutable-by-design
// mechanism present (ostree, transactional-update/MicroOS, SteamOS, or an immutable
// fstype). That's the fingerprint of an `errors=remount-ro` trip or a failed fsck —
// a degraded host. The collector returns this struct ONLY on the fault (nil
// otherwise), so a healthy host shows no row.
type RootFSInfo struct {
	UnexpectedReadOnly bool   `json:"unexpected_read_only"`
	RootFstype         string `json:"root_fstype,omitempty"`
}
