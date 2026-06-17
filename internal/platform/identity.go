package platform

import (
	"os"
	"sync"
)

// Identity override for `dsd replay`. The replaying machine's hostname/OS leak
// into a replayed report (render JSON, baseline snapshot) because they are read
// live (os.Hostname / /etc/os-release) rather than from the bundle. SetIdentity
// lets replay pin the CAPTURED host's identity (from the bundle manifest) so the
// report — and `dsd diff` — carry the right host, not the box doing the replay.
var (
	idMu         sync.RWMutex
	hostOverride string
	osOverride   string
)

// SetIdentity overrides Hostname() and OSPrettyName(). Empty strings leave that
// field reading live. Returns a restore func; callers should `defer` it.
func SetIdentity(host, osName string) (restore func()) {
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
