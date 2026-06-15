//go:build linux

package collectors

import "context"

// systemdNeedsReload returns units whose on-disk file changed since systemd
// loaded it (NeedsDaemonReload=yes) — i.e. the running service is on stale
// config. Wraps the shared collector so the cross-platform SystemdCollector can
// call it without referencing the linux-only symbol directly.
func systemdNeedsReload(ctx context.Context) []string { return collectNeedsDaemonReload(ctx) }
