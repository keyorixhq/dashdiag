//go:build linux

package collectors

import (
	"context"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// RootFSCollector detects an UNEXPECTED read-only root filesystem — the fingerprint
// of an `errors=remount-ro` trip or a failed boot-time fsck (a degraded host). It is
// deliberately self-guarding against the many distros that mount / read-only BY
// DESIGN: it only fires when the root is ro on a normally-writable fs, fstab intends
// it rw, AND no immutable mechanism (ostree, transactional-update, SteamOS, or an
// immutable fstype) is present. Returns nil (no row) on a healthy host.
type RootFSCollector struct{}

func NewRootFSCollector() *RootFSCollector { return &RootFSCollector{} }

func (c *RootFSCollector) Name() string           { return "Root FS" }
func (c *RootFSCollector) Timeout() time.Duration { return 2 * time.Second }

// writableRootFstypes are filesystems that are normally mounted read-write; a
// read-only mount of one is suspicious. Immutable image fstypes (squashfs, erofs,
// iso9660, overlay, cramfs) are intentionally absent — a ro mount of those is normal.
var writableRootFstypes = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true,
	"f2fs": true, "jfs": true, "reiserfs": true, "nilfs2": true,
}

func (c *RootFSCollector) Collect(_ context.Context) (interface{}, error) {
	data, err := readFile("/proc/mounts")
	if err != nil {
		return nil, nil // can't read mounts — nothing to assert
	}
	mounts, _ := readMounts(strings.NewReader(string(data)))
	var root *mountEntry
	for i := range mounts {
		if mounts[i].mountPoint == "/" {
			root = &mounts[i] // last "/" wins (the effective root mount)
		}
	}
	if root == nil || !root.readOnly {
		return nil, nil // no root entry, or root is rw — healthy
	}
	if !rootROIsUnexpected(root.fsType, fstabIntendsRootRW(), rootImmutableByDesign()) {
		return nil, nil // ro by design (immutable distro / image fstype / fstab says ro)
	}
	return &models.RootFSInfo{UnexpectedReadOnly: true, RootFstype: root.fsType}, nil
}

// rootROIsUnexpected is the pure decision: a read-only root is a FAULT only on a
// normally-writable fstype, when fstab intends rw, and nothing makes it ro by design.
func rootROIsUnexpected(fstype string, fstabRW, immutableByDesign bool) bool {
	if immutableByDesign || !writableRootFstypes[fstype] {
		return false
	}
	return fstabRW
}

// rootImmutableByDesign reports whether this host mounts / read-only by design —
// ostree (Fedora CoreOS/Silverblue/IoT), transactional-update (openSUSE MicroOS /
// transactional server), or SteamOS. All are runtime markers, source-routed.
func rootImmutableByDesign() bool {
	if fileExists("/run/ostree-booted") {
		return true
	}
	if fileExists("/usr/sbin/transactional-update") || fileExists("/sbin/transactional-update") {
		return true
	}
	return osReleaseIsSteamOS()
}

// osReleaseIsSteamOS checks /etc/os-release for the SteamOS id (steamos-readonly
// toggles a ro btrfs root by design). Source-routed read for replay fidelity.
func osReleaseIsSteamOS() bool {
	data, err := readFile("/etc/os-release")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "ID=steamos" || strings.HasPrefix(line, "VARIANT_ID=steamdeck") {
			return true
		}
	}
	return false
}

// fstabIntendsRootRW reports whether /etc/fstab has a `/` entry whose options imply
// read-write (no standalone `ro` option). Returns false when there is no `/` entry
// (root managed outside fstab — kernel cmdline, ostree, systemd) so an unverifiable
// intent never flags. The `errors=remount-ro` option is NOT the `ro` option.
func fstabIntendsRootRW() bool {
	data, err := readFile("/etc/fstab")
	if err != nil {
		return false
	}
	return fstabRootRW(string(data))
}

// fstabRootRW reports whether fstab has a `/` entry whose options imply read-write
// (no standalone `ro` option). False when there is no `/` entry (root managed
// outside fstab). `errors=remount-ro` is NOT the `ro` option (token-exact match).
func fstabRootRW(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 || f[1] != "/" {
			continue
		}
		for _, opt := range strings.Split(f[3], ",") {
			if opt == "ro" {
				return false // fstab explicitly mounts / read-only — ro is intended
			}
		}
		return true // a `/` entry with no `ro` option → rw intent
	}
	return false // no `/` entry in fstab → can't confirm rw intent
}
