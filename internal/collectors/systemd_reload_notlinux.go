//go:build !linux

package collectors

import "context"

// systemdNeedsReload is a no-op on non-Linux platforms (systemd is Linux-only;
// SystemdCollector.Collect already returns Available:false there).
func systemdNeedsReload(_ context.Context) []string { return nil }
