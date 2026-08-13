package platform

import (
	"os"
	"strings"
	"sync"
	"unicode"
)

// Identity override for `dsd replay`. The replaying machine's hostname/OS leak
// into a replayed report (render JSON, baseline snapshot) because they are read
// live (os.Hostname / /etc/os-release) rather than from the bundle. SetIdentity
// lets replay pin the CAPTURED host's identity (from the bundle manifest) so the
// report — and `dsd diff` — carry the right host, not the box doing the replay.
var (
	idMu               sync.RWMutex
	hostOverride       string
	osOverride         string
	distroIDOverride   string
	initSystemOverride string
	goosOverride       string
)

// stripControl removes control characters (including ESC, which starts
// ANSI/OSC/DCS terminal escape sequences) from s, leaving printable text
// unchanged. platform/ may only depend on stdlib (see CLAUDE.md's layered-
// import contract), so this duplicates the small amount of logic in
// internal/output.SanitizeControl rather than importing it.
func stripControl(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// SetReplayPlatform pins the captured host's distro ID, init system, and GOOS so the
// fix-hint adaptation on `dsd replay` reflects the CAPTURED host (the package manager
// in "to fix: <pm> install", the init system, the OS family for ss/systemctl), not the
// box doing the replay. Empty strings leave a field reading live (older bundles that
// predate these manifest fields). Returns a restore func; callers should defer it.
//
// distroID/initSystem/goos come from a capture bundle manifest — untrusted
// input per the product's own threat model — with no length limit or
// character allowlist upstream, so control/ANSI-escape bytes are stripped
// here before they can reach a rendered report header.
func SetReplayPlatform(distroID, initSystem, goos string) (restore func()) {
	distroID = stripControl(distroID)
	initSystem = stripControl(initSystem)
	goos = stripControl(goos)
	idMu.Lock()
	prevD, prevI, prevG := distroIDOverride, initSystemOverride, goosOverride
	distroIDOverride, initSystemOverride, goosOverride = distroID, initSystem, goos
	idMu.Unlock()
	return func() {
		idMu.Lock()
		distroIDOverride, initSystemOverride, goosOverride = prevD, prevI, prevG
		idMu.Unlock()
	}
}

// ReplayDistroID / ReplayInitSystem / ReplayGOOS return the replay override, or "" when
// not replaying (callers fall back to live detection).
func ReplayDistroID() string   { idMu.RLock(); defer idMu.RUnlock(); return distroIDOverride }
func ReplayInitSystem() string { idMu.RLock(); defer idMu.RUnlock(); return initSystemOverride }
func ReplayGOOS() string       { idMu.RLock(); defer idMu.RUnlock(); return goosOverride }

// SetIdentity overrides Hostname() and OSPrettyName(). Empty strings leave that
// field reading live. Returns a restore func; callers should `defer` it.
//
// host/osName come from a capture bundle manifest — untrusted input per the
// product's own threat model — with no length limit or character allowlist
// upstream, so control/ANSI-escape bytes are stripped here before they can
// reach a rendered report header (e.g. "host · OS").
func SetIdentity(host, osName string) (restore func()) {
	host = stripControl(host)
	osName = stripControl(osName)
	idMu.Lock()
	prevHost, prevOS := hostOverride, osOverride
	hostOverride, osOverride = host, osName
	idMu.Unlock()
	return func() {
		idMu.Lock()
		hostOverride, osOverride = prevHost, prevOS
		idMu.Unlock()
	}
}

// Hostname returns the identity override if set, else the live os.Hostname().
func Hostname() string {
	idMu.RLock()
	h := hostOverride
	idMu.RUnlock()
	if h != "" {
		return h
	}
	n, _ := os.Hostname()
	return n
}

// osIdentityOverride returns the OS-name override (or "" for none).
func osIdentityOverride() string {
	idMu.RLock()
	defer idMu.RUnlock()
	return osOverride
}
