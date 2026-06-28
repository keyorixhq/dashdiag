//go:build linux

package collectors

// hostRootImmutable reports whether the host mounts / read-only BY DESIGN (ostree,
// transactional-update/MicroOS, SteamOS). It wraps rootImmutableByDesign (defined in
// rootfs_linux.go) so the cross-platform disk collector can call it without a build
// tag. Source-routed reads → replay-faithful.
func hostRootImmutable() bool { return rootImmutableByDesign() }
