//go:build linux

package collectors

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
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
		nfsCheckServer(ctx, m)
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
	data, err := os.ReadFile("/proc/mounts") // #nosec G304
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
		var st syscall.Statfs_t
		err := syscall.Statfs(m.Mount, &st)
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

func nfsCheckServer(ctx context.Context, m *models.NFSMount) {
	if m.Server == "" || m.Server == "127.0.0.1" || m.Server == "localhost" {
		// Loopback — always reachable; port check still useful
		m.ServerReachable = true
	} else {
		m.ServerReachable = nfsPingServer(ctx, m.Server)
	}
	m.NFSPortOpen = nfsCheckPort(ctx, m.Server, 2049)
}

// nfsPingServer does a TCP connect to port 111 (rpcbind) as a reachability probe.
// ICMP ping requires CAP_NET_RAW; TCP connect works without special privileges.
func nfsPingServer(ctx context.Context, server string) bool {
	d := net.Dialer{Timeout: 1 * time.Second}
	connCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	conn, err := d.DialContext(connCtx, "tcp", server+":111")
	if err == nil {
		conn.Close() //nolint:errcheck
		return true
	}
	// Fallback: try port 2049 directly
	conn2, err2 := d.DialContext(connCtx, "tcp", server+":2049")
	if err2 == nil {
		conn2.Close() //nolint:errcheck
		return true
	}
	return false
}

// nfsCheckPort tests TCP connectivity to a specific port.
func nfsCheckPort(ctx context.Context, server string, port int) bool {
	d := net.Dialer{Timeout: 1 * time.Second}
	connCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	conn, err := d.DialContext(connCtx, "tcp", fmt.Sprintf("%s:%d", server, port))
	if err != nil {
		return false
	}
	conn.Close() //nolint:errcheck
	return true
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
	data, err := os.ReadFile("/etc/fstab") // #nosec G304
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "#") || !strings.Contains(line, m.Mount) {
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
	out, err := runCmd(ctx, "systemctl", "is-active", "rpcbind")
	return err == nil && strings.TrimSpace(out) == "active"
}

// nfsReadStats reads /proc/net/rpc/nfs and parses operation counts.
// Format: line starting with "rpc" has: calls retransmissions authrefrsh
func nfsReadStats(info *models.NFSInfo) {
	data, err := os.ReadFile("/proc/net/rpc/nfs") // #nosec G304
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
			// calls retrans authrefrsh
			if len(fields) >= 3 {
				retrans, _ := strconv.ParseFloat(fields[2], 64)
				info.RetransPerMin = retrans // raw counter; caller compares with previous
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
					reads, _ = strconv.ParseFloat(fields[2], 64)
				}
				if len(fields) > 3 {
					writes, _ = strconv.ParseFloat(fields[3], 64)
				}
				info.ReadOpsPerMin = reads
				info.WriteOpsPerMin = writes
			}
		}
	}
}
