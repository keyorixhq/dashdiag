package collectors

// netaccess.go — cross-platform reachability probe routed through the active
// source. Kept untagged (not _linux) because the docker collector, which builds
// on darwin too, gates on it.

import (
	"net"
	"strings"
	"time"
)

// dialState is the outcome of a cached reachability probe.
type dialState int

const (
	dialUnreachable dialState = iota // nothing accepting (or recording gap)
	dialOK                           // connection accepted
	dialPermission                   // present but the dial was permission-denied
)

// dialOutcome probes addr and returns a three-state result, routed through the
// source cache so a service gate replays from the bundle instead of dialing the
// replaying machine. The permission-denied case is preserved distinctly because
// some collectors branch on it (e.g. the docker socket: present but not
// accessible). The probe never errors — the outcome is recorded as a single byte
// ('1' ok, 'p' permission, '0' unreachable) so replay reproduces capture-time
// reachability. On a recording gap (older bundle) it returns dialUnreachable.
func dialOutcome(network, addr string, timeout time.Duration) dialState {
	data, _ := activeSource.Cached("dial/"+network+"/"+addr, func() ([]byte, error) {
		conn, derr := net.DialTimeout(network, addr, timeout)
		if derr == nil {
			_ = conn.Close()
			return []byte{'1'}, nil
		}
		if strings.Contains(derr.Error(), "permission denied") {
			return []byte{'p'}, nil
		}
		return []byte{'0'}, nil
	})
	if len(data) != 1 {
		return dialUnreachable
	}
	switch data[0] {
	case '1':
		return dialOK
	case 'p':
		return dialPermission
	default:
		return dialUnreachable
	}
}
