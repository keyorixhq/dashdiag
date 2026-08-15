//go:build linux

package collectors

// socketpeer_linux.go — kernel-verified identity of the process on the other
// end of a local unix-domain socket, via SO_PEERCRED. Used before a collector
// treats a service found at a predictable, sometimes world-writable path
// (e.g. /tmp/mysql.sock) as the real service rather than an impostor
// listener planted by an unprivileged local attacker.
//
// SO_PEERCRED is answered by the KERNEL from the connecting process's actual
// credentials at connect(2) time — it cannot be spoofed by the peer process,
// unlike anything the peer could claim over its own wire protocol. That is
// what makes it a sound trust check where "does the service answer
// SELECT VERSION() correctly" is not: an attacker-controlled listener can
// answer arbitrary bytes on the socket, including a fabricated protocol
// handshake, but it cannot fabricate its own kernel-reported UID.
//
// Routed through curSource().Cached() (the extension point source.Source
// already documents for "inputs that don't map to a single file read... a
// gopsutil call that reads /proc through its own API") rather than through a
// raw live syscall or a new Source method: Live invokes the probe on every
// collection, Recorder invokes it once and records the result, and Replay
// returns the recorded bytes and NEVER dials the replaying machine's own
// socket — which wouldn't exist, or worse, could be a completely different,
// locally-controlled process on the developer/CI box replaying the bundle.
// This preserves the "replay never makes a live syscall" hermeticity
// guarantee without touching the Source interface or FileMeta.

import (
	"encoding/json"
	"net"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

// peerCredDialTimeout bounds the live SO_PEERCRED probe dial, matching the
// short timeouts the sibling dialReachable probes in netaccess.go use for
// local service gates.
const peerCredDialTimeout = 300 * time.Millisecond

// socketPeerCred is the trust-relevant identity of the process on the other
// end of a unix socket, as reported by the kernel at connect(2) time.
type socketPeerCred struct {
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
	Present bool   `json:"present"` // false = probe failed (socket gone, not AF_UNIX, kernel refused SO_PEERCRED)
}

// probeSocketPeerCred returns the kernel-verified identity of the process
// listening on sockPath, routed through the active source's Cached() so a
// replay serves the value recorded at capture time. A recording gap (older
// bundle, captured before this check existed) or a probe failure both
// resolve to Present:false — callers must treat that as "could not verify",
// never as "trusted".
func probeSocketPeerCred(sockPath string) socketPeerCred {
	data, err := curSource().Cached("socketpeercred/"+sockPath, func() ([]byte, error) {
		return json.Marshal(livePeerCred(sockPath))
	})
	if err != nil {
		return socketPeerCred{}
	}
	var c socketPeerCred
	if err = json.Unmarshal(data, &c); err != nil {
		return socketPeerCred{}
	}
	return c
}

// livePeerCred performs the actual dial + SO_PEERCRED syscall. Only ever
// called from within the Cached() produce closure above: Live invokes it on
// every collection, Recorder invokes it once and records the bytes, Replay
// never invokes it at all.
func livePeerCred(sockPath string) socketPeerCred {
	conn, err := net.DialTimeout("unix", sockPath, peerCredDialTimeout)
	if err != nil {
		return socketPeerCred{}
	}
	defer conn.Close() //nolint:errcheck

	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return socketPeerCred{}
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return socketPeerCred{}
	}
	var cred *syscall.Ucred
	var gerr error
	cerr := raw.Control(func(fd uintptr) {
		cred, gerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if cerr != nil || gerr != nil || cred == nil {
		return socketPeerCred{}
	}
	return socketPeerCred{UID: cred.Uid, GID: cred.Gid, Present: true}
}

// lookupUserUID resolves username to a UID, routed through Cached() so
// replay reproduces the CAPTURED host's /etc/passwd mapping (via os/user,
// which reads NSS sources outside the source-routed file helpers) rather
// than the replaying machine's own accounts. "user not found" is recorded as
// a real, non-error outcome (-1) — it is itself a fact about the captured
// host, not a probe failure.
func lookupUserUID(username string) (uid uint32, ok bool) {
	data, err := curSource().Cached("userlookup/"+username, func() ([]byte, error) {
		u, uerr := user.Lookup(username)
		if uerr != nil {
			return []byte("-1"), nil
		}
		return []byte(u.Uid), nil
	})
	if err != nil {
		return 0, false
	}
	raw := string(data)
	if raw == "-1" {
		return 0, false
	}
	// ParseUint with bitSize 32 rejects a value that doesn't fit in uint32
	// outright, instead of a plain Atoi+cast silently wrapping it.
	n, perr := strconv.ParseUint(raw, 10, 32)
	if perr != nil {
		return 0, false
	}
	return uint32(n), true
}

// socketPeerTrusted reports whether the process on the other end of sockPath
// is root (uid 0) or runs as the named service account (e.g. "mysql",
// "postgres") — a sound trust boundary for a collector about to run a client
// against a predictable, occasionally world-writable socket path.
//
// verified is false when the SO_PEERCRED probe itself could not be
// completed (socket gone between the reachability gate and this call, not
// really AF_UNIX, or a recording gap under replay) — in that case trusted is
// always false too, and callers must disclose "ownership unverified" rather
// than silently proceeding as if the check had passed OR silently treating
// it as a confirmed impostor.
func socketPeerTrusted(sockPath, serviceAccount string) (trusted, verified bool) {
	cred := probeSocketPeerCred(sockPath)
	if !cred.Present {
		return false, false
	}
	if cred.UID == 0 {
		return true, true
	}
	svcUID, ok := lookupUserUID(serviceAccount)
	if !ok {
		// Probe succeeded (we know the peer's real UID) but the expected
		// service account doesn't resolve on this host — can't confirm a
		// match, so treat as untrusted. The probe itself is still "verified"
		// (we have a real answer, just not a trusted one).
		return false, true
	}
	return cred.UID == svcUID, true
}
