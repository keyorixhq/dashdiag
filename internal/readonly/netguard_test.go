//go:build linux

// Package readonly (test-only) is RO1's end-to-end harness for DashDiag's
// central product claim: "read-only, and never talks to the network from a
// collector". It runs every collector in-process with three independent
// watchdogs armed — a filesystem fingerprint (reused DL1 resource oracle), an
// exec allowlist fed by platform.ExecHook, and a network dial guard — then
// fuzzes the environment, fake procfs/sysfs, hostname and flag-like tokens that
// feed them.
//
// This file owns the NETWORK guard: it replaces http.DefaultTransport and
// net.DefaultResolver so that any dial to a non-loopback address is recorded as
// a violation (and denied). The guard is installed once, in TestMain
// (main_test.go), and read per-input by the fuzz target (harness_test.go).
//
// It is deliberately a test-only package (every file is _test.go): production
// dsd must never carry any of this, and platform.ExecHook must stay nil outside
// a test binary.
package readonly

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// dialViolation is one non-loopback dial attempt the guard caught.
type dialViolation struct {
	Network string
	Address string
	Via     string // "http.DefaultTransport" or "net.DefaultResolver"
}

// netGuard records every non-loopback dial attempt made through the two seams
// we control (http.DefaultTransport, net.DefaultResolver). It never actually
// opens a non-loopback connection: the guard returns an error before dialing,
// so even a real violation cannot reach the network on this unsandboxed host.
type netGuard struct {
	mu         sync.Mutex
	violations []dialViolation
}

var guard = &netGuard{}

// errNonLoopbackDenied is returned to the caller so the dial fails exactly like
// a real network error would — the collector degrades, nothing leaves the host.
var errNonLoopbackDenied = errors.New("ro1-netguard: non-loopback dial denied")

// isLoopbackAddr reports whether a host:port (or bare host) names the loopback
// interface. A bare "localhost" counts as loopback; an unresolved non-loopback
// hostname (e.g. "example.com", "169.254.169.254") does NOT — a dial to it is a
// network attempt whether or not DNS would have resolved it.
func isLoopbackAddr(address string) bool {
	host := address
	if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	// A non-IP, non-"localhost" host is a name we'd have to resolve off-box —
	// treat as non-loopback (a violation of the no-network claim).
	return false
}

// record logs a violation and returns the deny error.
func (g *netGuard) record(network, address, via string) error {
	g.mu.Lock()
	g.violations = append(g.violations, dialViolation{Network: network, Address: address, Via: via})
	g.mu.Unlock()
	return errNonLoopbackDenied
}

// count returns how many violations have been recorded so far. The fuzz target
// snapshots this before a run and after, so each input is judged on its own
// dials, not the whole process's history.
func (g *netGuard) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.violations)
}

// since returns the violations recorded at or after index n.
func (g *netGuard) since(n int) []dialViolation {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n < 0 || n > len(g.violations) {
		n = 0
	}
	out := make([]dialViolation, len(g.violations)-n)
	copy(out, g.violations[n:])
	return out
}

// guardedDialContext allows loopback dials (so a collector probing a local
// listener still works) and records+denies everything else.
func guardedDialContext(via string) func(context.Context, string, string) (net.Conn, error) {
	var d net.Dialer
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if !isLoopbackAddr(address) {
			return nil, guard.record(network, address, via)
		}
		return d.DialContext(ctx, network, address)
	}
}

// installNetGuard replaces http.DefaultTransport and net.DefaultResolver with
// loopback-only, recording variants. Called once from TestMain.
func installNetGuard() {
	tr := &http.Transport{
		Proxy:                 nil, // ignore any HTTP(S)_PROXY — a proxy dial is still a non-loopback dial we want to catch directly
		DialContext:           guardedDialContext("http.DefaultTransport"),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       5 * time.Second,
		TLSHandshakeTimeout:   2 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	http.DefaultTransport = tr

	net.DefaultResolver = &net.Resolver{
		PreferGo: true, // force the pure-Go resolver so our Dial is actually used (cgo resolver would bypass it)
		Dial:     guardedDialContext("net.DefaultResolver"),
	}
}
