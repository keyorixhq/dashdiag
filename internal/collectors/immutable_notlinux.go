//go:build !linux

package collectors

// hostRootImmutable is linux-only; non-Linux platforms have no immutable-root
// distro family (ostree / transactional-update / SteamOS), so this is always false.
func hostRootImmutable() bool { return false }
