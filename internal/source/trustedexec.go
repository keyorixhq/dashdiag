package source

import (
	"os"
	"path/filepath"
	"strings"
)

// trustedToolDirs lists the directories dsd trusts when resolving an external
// tool invoked by bare name — deliberately NOT the process's inherited $PATH.
// dsd routinely runs as root (full checks need it), and a root process that
// blindly honors $PATH is a PATH-hijack vector: a malicious directory
// prepended ahead of the real system dirs (a tampered shell profile, a
// leftover sudo environment, a compromised PATH-setting init script) would
// otherwise run an attacker's binary in place of the real tool for every
// external command dsd shells out to. Covers the standard locations every
// tool dsd invokes actually ships in, across Linux and macOS (incl. both
// Intel and Apple Silicon Homebrew prefixes).
var trustedToolDirs = []string{
	"/usr/sbin", "/usr/bin", "/sbin", "/bin",
	"/usr/local/sbin", "/usr/local/bin",
	"/opt/homebrew/sbin", "/opt/homebrew/bin",
}

// ResolveTrustedTool resolves name to an absolute path by searching
// trustedToolDirs, in order, never the process's inherited $PATH.
//
//   - An explicit path (containing a "/") is returned unchanged — the caller
//     already made a deliberate choice, this only hardens BARE-NAME lookups.
//   - A name that resolves to nothing in the trusted directories is returned
//     unchanged too, so the subsequent exec fails with the same "executable
//     file not found" error as before: this only removes the untrusted-$PATH
//     search, it never changes tool-absent behavior or capture/replay command
//     keys (callers that must keep a stable key — e.g. firewall_linux.go's
//     nft/iptables invocations — pass the bare name in either case; this
//     function is applied deeper, only at the point of actually exec'ing).
func ResolveTrustedTool(name string) string {
	if strings.Contains(name, "/") {
		return name
	}
	for _, dir := range trustedToolDirs {
		candidate := filepath.Join(dir, name)
		fi, err := os.Stat(candidate)
		if err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return candidate
		}
	}
	return name
}
