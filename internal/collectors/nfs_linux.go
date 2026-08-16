//go:build linux

package collectors

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// NFSCollector checks NFS mount health without hanging.
// The critical technique: non-blocking syscall.Statfs in a goroutine with 2s timeout.
// A direct stat on a stale NFS mount hangs the caller indefinitely (D-state).
type NFSCollector struct{}

func NewNFSCollector() *NFSCollector           { return &NFSCollector{} }
func (c *NFSCollector) Name() string           { return "NFS" }
func (c *NFSCollector) Timeout() time.Duration { return 15 * time.Second }

func (c *NFSCollector) Collect(ctx context.Context) (interface{}, error) {
	mounts := parseNFSMounts()
	if len(mounts) == 0 {
		return nil, nil // no NFS mounts — caller omits section
	}

	info := &models.NFSInfo{}
	info.RpcbindActive = nfsRpcbindActive(ctx)
	nfsReadStats(info)

	for i := range mounts {
		m := &mounts[i]
		nfsCheckMount(ctx, m)
		nfsCheckServer(m)
		nfsAuditOptions(m)
		if m.Stale {
			info.StaleMounts++
		}
		info.Mounts = append(info.Mounts, *m)
	}

	return info, nil
}

// ── mount parsing ─────────────────────────────────────────────────────────────

func parseNFSMounts() []models.NFSMount {
	data, err := readFile("/proc/mounts") // #nosec G304
	if err != nil {
		return nil
	}
	var mounts []models.NFSMount
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		fstype := fields[2]
		if fstype != "nfs" && fstype != "nfs4" {
			continue
		}
		// fields[0] = "server:/export", fields[1] = mountpoint
		source := fields[0]
		server, export := nfsParseSource(source)
		mounts = append(mounts, models.NFSMount{
			Mount:   fields[1],
			Server:  server,
			Export:  export,
			FSType:  fstype,
			Options: fields[3],
		})
	}
	return mounts
}

// nfsParseSource splits "server:/export" or "server" into (server, export).
func nfsParseSource(source string) (server, export string) {
	if idx := strings.Index(source, ":/"); idx >= 0 {
		return source[:idx], source[idx+1:]
	}
	if idx := strings.Index(source, ":"); idx >= 0 {
		return source[:idx], source[idx+1:]
	}
	return source, "/"
}

// ── stale mount detection ─────────────────────────────────────────────────────

// nfsCheckMount runs syscall.Statfs in a goroutine with a 2s timeout.
// This is the only safe way to check NFS mount health — direct stat hangs
// indefinitely on stale mounts (process goes into D-state).
func nfsCheckMount(ctx context.Context, m *models.NFSMount) {
	type result struct {
		latencyMs int
		err       error
	}
	ch := make(chan result, 1)
	start := time.Now()

	go func() {
		_, err := statFs(m.Mount)
		ch <- result{int(time.Since(start).Milliseconds()), err}
	}()

	// 2s timeout — if no response, mount is stale
	deadline := time.After(2 * time.Second)
	select {
	case r := <-ch:
		if r.err == nil {
			m.Healthy = true
			m.LatencyMs = r.latencyMs
		} else {
			m.Healthy = false
			// A PROMPT error (not the 2s hang below) still means the mount is broken.
			// ESTALE ("Stale file handle") and EIO (server gone) are the cases where
			// accessing it hangs processes in D-state — flag them as stale so the
			// verdict fires. Previously only the timeout path set Stale, so a mount
			// that returned ESTALE immediately read as a non-event (false-OK).
			if errors.Is(r.err, syscall.ESTALE) || errors.Is(r.err, syscall.EIO) {
				m.Stale = true
			}
		}
	case <-deadline:
		m.Stale = true
		m.Healthy = false
	case <-ctx.Done():
		m.Stale = true
		m.Healthy = false
	}
}

// ── server reachability ───────────────────────────────────────────────────────

func nfsCheckServer(m *models.NFSMount) {
	isLoopback := m.Server == "" || m.Server == "127.0.0.1" || m.Server == "localhost"
	// A non-loopback server dial leaves the machine, to a host taken from the
	// mount table — not fully trusted (e.g. a container/namespace's mount
	// table can be set up by whoever configured that namespace). Skip that
	// dial unless network is allowed (platform.NetworkAllowed — off by
	// default) rather than reporting a fabricated "unreachable" —
	// ServerCheckSkipped tells the heuristic this is unmeasured, not a real
	// finding. The loopback case never leaves the machine, so it is unaffected.
	// sourceIsReplaying short-circuits the gate under `dsd replay`: nfsPingServer/
	// nfsCheckPort route through dialReachable's source-cached dial, which on
	// replay serves the recorded reachability and never dials live — gating
	// the call site itself would fabricate "skipped" over a real recording
	// (see TestNFSReachabilityReplaysFromBundle).
	if !isLoopback && !platform.NetworkAllowed() && !sourceIsReplaying() {
		m.ServerCheckSkipped = true
		return
	}
	if isLoopback {
		// Loopback — always reachable; port check still useful
		m.ServerReachable = true
	} else {
		m.ServerReachable = nfsPingServer(m.Server)
	}
	m.NFSPortOpen = nfsCheckPort(m.Server, 2049)
}

// nfsPingServer does a TCP connect to port 111 (rpcbind) as a reachability probe.
// ICMP ping requires CAP_NET_RAW; TCP connect works without special privileges.
// Routed through the source (dialReachable → dialOutcome) so the probe replays from
// the bundle instead of dialing the replaying machine under `dsd replay`.
func nfsPingServer(server string) bool {
	// Fallback to 2049 directly if rpcbind (111) is closed.
	return dialReachable("tcp", server+":111", time.Second) ||
		dialReachable("tcp", server+":2049", time.Second)
}

// nfsCheckPort tests TCP connectivity to a specific port (routed through source).
func nfsCheckPort(server string, port int) bool {
	return dialReachable("tcp", fmt.Sprintf("%s:%d", server, port), time.Second)
}

// ── mount option audit ────────────────────────────────────────────────────────

func nfsAuditOptions(m *models.NFSMount) {
	opts := make(map[string]string)
	for _, opt := range strings.Split(m.Options, ",") {
		if idx := strings.Index(opt, "="); idx >= 0 {
			opts[opt[:idx]] = opt[idx+1:]
		} else {
			opts[opt] = ""
		}
	}

	if _, soft := opts["soft"]; soft {
		if _, hasTimeo := opts["timeo"]; !hasTimeo {
			m.OptionsWarnings = append(m.OptionsWarnings,
				"soft mount without timeo — silent data loss on timeout")
		}
	}
	if _, ok := opts["nolock"]; ok {
		m.OptionsWarnings = append(m.OptionsWarnings,
			"nolock — file locking disabled, risk of data corruption if share is multi-client")
	}
	if ver, ok := opts["vers"]; ok && (ver == "2" || ver == "3") {
		m.OptionsWarnings = append(m.OptionsWarnings,
			fmt.Sprintf("NFSv%s — consider upgrading to vers=4 for better reliability and security", ver))
	}
	// Check fstab for missing _netdev
	nfsCheckFstab(m)
}

// nfsCheckFstab checks for missing _netdev option which causes boot hangs.
func nfsCheckFstab(m *models.NFSMount) {
	data, err := readFile("/etc/fstab") // #nosec G304
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue // fully-commented or blank line
		}
		// Strip a trailing inline comment (e.g. "... nfs rw 0 0  # backups") —
		// a real, active mount entry with one was previously treated as fully
		// commented-out and never matched against m.Mount, silently skipping
		// the _netdev check even when _netdev really was absent from it.
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		if !strings.Contains(line, m.Mount) {
			continue
		}
		if strings.Contains(line, m.Server) || strings.Contains(line, "nfs") {
			if !strings.Contains(line, "_netdev") {
				m.OptionsWarnings = append(m.OptionsWarnings,
					"_netdev missing from fstab — may cause boot hang if network not ready")
			}
			return
		}
	}
}

// ── rpcbind + NFS stats ───────────────────────────────────────────────────────

func nfsRpcbindActive(ctx context.Context) bool {
	if out, err := runCmd(ctx, "systemctl", "is-active", "rpcbind"); err == nil && strings.TrimSpace(out) == "active" {
		return true
	}
	// Non-systemd host (Alpine/OpenRC/Devuan): systemctl is absent, so confirm via
	// the running process instead of false-alarming "rpcbind not running".
	return anyProcessNamed("rpcbind", "rpc.statd")
}

// nfsReadStats reads /proc/net/rpc/nfs and parses operation counts.
// Format: line starting with "rpc" has: calls retransmissions authrefrsh
func nfsReadStats(info *models.NFSInfo) {
	data, err := readFile("/proc/net/rpc/nfs") // #nosec G304
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		switch fields[0] {
		case "rpc":
			// fields: rpc <calls> <retrans> <authrefresh> — both cumulative since boot.
			// Capture calls too so the verdict can gate on the retrans RATE (retrans/calls)
			// rather than a raw lifetime total that never decays.
			if len(fields) >= 3 {
				info.RPCCalls = parseFloat(fields[1])
				info.RetransPerMin = parseFloat(fields[2])
			}
		case "proc4":
			// NFSv4 operations: count null read write commit ...
			// fields[1] = count, then one field per op
			// "read" is index ~2, "write" is ~3 (varies by kernel)
			// Sum all non-null ops as total
			if len(fields) > 3 {
				var reads, writes float64
				// Typical v4 proc order: null read write commit ...
				if len(fields) > 2 {
					reads = parseFloat(fields[2])
				}
				if len(fields) > 3 {
					writes = parseFloat(fields[3])
				}
				info.ReadOpsPerMin = reads
				info.WriteOpsPerMin = writes
			}
		}
	}
}
