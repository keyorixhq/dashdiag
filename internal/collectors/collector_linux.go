//go:build linux

package collectors

import "os"

// geteuid/getuid are seams over os.Geteuid/os.Getuid so tests can exercise the
// root and non-root branches of root-gated collectors deterministically,
// regardless of the uid the test binary actually runs under. CI runs the Linux
// jobs as a non-root user, so a collector that gates privileged probes on
// os.Geteuid()==0 would otherwise be untestable there (same var-seam pattern as
// runCmd/lookPath in collector.go). Swap via swapGeteuid/swapGetuid in tests.
// Linux-only: no darwin collector currently gates on euid/uid.
var (
	geteuid = os.Geteuid
	getuid  = os.Getuid
)
