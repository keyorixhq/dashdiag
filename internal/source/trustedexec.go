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
	// Not found in any trusted directory. Returning the bare name here would let
	// exec.Command/CommandContext perform ITS OWN PATH search: Go's os/exec calls
	// LookPath internally whenever the given name has no path separator
	// (filepath.Base(name) == name), which searches the process's inherited
	// $PATH — exactly the untrusted search this function exists to remove. A
	// caller that resolves a bare tool name via an unrestricted-$PATH lookup
	// (e.g. collectors/k8s.go's k8sDetectBin PATH fallback for k3s/k0s/
	// microk8s/kubectl) and then hands that same bare name to runCmd would
	// silently regain the exact PATH-hijack this function was written to close:
	// a directory writable by an unprivileged user, placed ahead of the real
	// tool on a root process's PATH (sudo -E, a permissive secure_path, a
	// container image with a writable early PATH entry), would still win.
	// Anchor the name under a directory that can never exist so the caller's
	// exec fails cleanly with "no such file or directory" instead — this
	// still only removes the untrusted-$PATH search (never changes tool-
	// absent behavior or capture/replay command keys, which are keyed on the
	// original name before this function runs), it just closes the gap where
	// "not found in trusted dirs" fell through to Go's own PATH resolution.
	return filepath.Join("/nonexistent-dsd-trusted-tool", name)
}
