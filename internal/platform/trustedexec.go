package platform

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// This file was moved here from internal/source (P2): the whole file was
// already pure stdlib with no coupling to source's own machinery (the
// Source interface, Live/Replay/Recorder, Bundle) — it just happened to be
// filed under a package it didn't need. Every prior external caller
// (source.ResolveTrustedTool, source.HardenedEnv, source.ExecWaitDelay) now
// calls platform.ResolveTrustedTool / platform.HardenedEnv /
// platform.ExecWaitDelay directly — no re-exported alias kept in source, so
// there is exactly one name for each primitive, not two.

// ExecWaitDelay bounds how long a subprocess gets to exit gracefully after its
// context is cancelled before *exec.Cmd force-kills it. Every hardened exec
// site in dsd uses this same value, so a wedged external tool (smartctl on a
// failing drive, ps on a stuck kernel table) can't outlive its caller's
// timeout.
const ExecWaitDelay = 100 * time.Millisecond

// HardenedEnv returns the process environment with the locale forced to C
// (LC_ALL=C, LANG=C), so any external command whose output is parsed emits
// stable English/ASCII (month/day names, decimal separators, status words)
// regardless of the host's locale — e.g. `dmesg -T` prints "dom jun" on
// es_ES, which an English-assuming parser cannot read (see dsd's own #82).
// Every external command whose stdout/stderr is later parsed should set
// cmd.Env = platform.HardenedEnv(). A call site that only inspects the exit
// code and never reads stdout/stderr does not need this — but say so in a
// comment at the call site ("exit code only; add HardenedEnv() if this ever
// parses stdout"), not just decide it silently: the reason expires the
// moment someone changes the call site to read output.
func HardenedEnv() []string {
	return append(os.Environ(), "LC_ALL=C", "LANG=C")
}

// trustedToolDirs lists the directories dsd trusts when resolving an external
// tool invoked by bare name — deliberately NOT the process's inherited $PATH.
// dsd routinely runs as root (full checks need it), and a root process that
// blindly honors $PATH is a PATH-hijack vector: a malicious directory
// prepended ahead of the real system dirs (a tampered shell profile, a
// leftover sudo environment, a compromised PATH-setting init script) would
// otherwise run an attacker's binary in place of the real tool for every
// external command dsd shells out to. Covers the standard locations every
// tool dsd invokes actually ships in, across Linux and macOS (incl. both
// Intel and Apple Silicon Homebrew prefixes). Being on this list is
// necessary but not sufficient — see dirIsRootSafe below: several of these
// entries are not actually root-owned on a real host, and ResolveTrustedTool
// only trusts them AS root when they also pass that check.
var trustedToolDirs = []string{
	"/usr/sbin", "/usr/bin", "/sbin", "/bin",
	"/usr/local/sbin", "/usr/local/bin",
	"/opt/homebrew/sbin", "/opt/homebrew/bin",
}

// geteuid is os.Geteuid behind a var so tests can simulate running as root
// without actually needing to.
var geteuid = os.Geteuid

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
//   - When dsd itself is running as root, a candidate directory that is not
//     ITSELF root-owned and locked down (no group/other write bit) is
//     skipped entirely, even though it's on the trusted list — see
//     dirIsRootSafe.
func ResolveTrustedTool(name string) string {
	if strings.Contains(name, "/") {
		return name
	}
	root := geteuid() == 0
	for _, dir := range trustedToolDirs {
		if root && !dirOwnedAndLockedByRoot(dir) {
			continue
		}
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

// dirOwnedAndLockedByRoot reports whether dir is safe for a ROOT dsd process
// to trust: owned by root (uid 0) and not writable by group or other. Only
// consulted when dsd itself is root — for the same reason PATH-trust exists
// at all: a non-root dsd process trusting a user-writable directory grants a
// local attacker nothing they didn't already have.
//
// "Trusted system directory" otherwise means nothing on its own: on macOS,
// Homebrew's prefix (/opt/homebrew) is owned by the installing user, not
// root, by Homebrew's own design; /usr/local is frequently left group- or
// world-writable on both platforms by local convention or a prior
// misconfigured install. A dsd process running as root that still honored
// either would be resolving a "trusted" name to a directory a local,
// unprivileged attacker can plant a binary into — the exact hijack this
// function exists to close, one level down from $PATH itself.
//
// Known, accepted cost: on a macOS host where dsd runs as root (sudo) and a
// diagnostic tool is ONLY installed via Homebrew, that tool is no longer
// resolved — /opt/homebrew's non-root ownership fails this check. The
// collector consuming it degrades exactly as it already does for any other
// "tool absent" case (nil / gated off, per the project's own gate-pattern
// convention), not a false result — the safe direction to fail in.
func dirOwnedAndLockedByRoot(dir string) bool {
	fi, err := os.Stat(dir)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false // can't verify ownership on this platform — fail closed
	}
	return dirIsRootSafe(st.Uid, fi.Mode())
}

// dirIsRootSafe is the pure decision dirOwnedAndLockedByRoot stats for: root
// ownership (uid 0) and no group/other write bit (mode&0o022 == 0). Split out
// so it's testable with synthetic uid/mode values, independent of what the
// test process's own real privilege or filesystem happens to allow.
func dirIsRootSafe(uid uint32, mode os.FileMode) bool {
	return uid == 0 && mode.Perm()&0o022 == 0
}
