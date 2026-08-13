//go:build linux

package collectors

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// memcachedCmd routes memcachedCmdLive through the source cache so the socket
// exchange replays from the bundle instead of re-dialling the replaying machine.
// Keyed by addr+cmd — safe as long as a given (addr, cmd) pair is issued at
// most once per run. Collect() issues "stats" TWICE (before/after a sleep, to
// detect active eviction) — use memcachedCmdSampled for that case so the two
// temporally-distinct reads get distinct cache keys instead of colliding.
func memcachedCmd(ctx context.Context, network, addr, cmd string, untilEND bool) (string, bool) {
	return memcachedCmdSampled(ctx, network, addr, cmd, cmd, untilEND)
}

// memcachedCmdSampled is memcachedCmd with an explicit cache-key discriminator
// (sample) distinct from the wire command (cmd) actually sent. Two calls with
// the same cmd but different sample values are recorded as separate blobs in a
// capture bundle and replay independently — required when the same protocol
// command is issued more than once per run to observe a value changing over
// time (e.g. two "stats" reads a few hundred ms apart). Without this, the
// Recorder's single blob-per-key store overwrites the first read with the
// second, and both calls replay identically — collapsing any before/after
// delta to zero.
func memcachedCmdSampled(ctx context.Context, network, addr, cmd, sample string, untilEND bool) (string, bool) {
	var r struct {
		Out string `json:"out"`
		Ok  bool   `json:"ok"`
	}
	_ = cachedJSON("memcached/"+network+"/"+addr+"/"+sample, func() (any, error) {
		out, ok := memcachedCmdLive(ctx, network, addr, cmd, untilEND)
		r.Out, r.Ok = out, ok
		return r, nil
	}, &r)
	return r.Out, r.Ok
}

// memcachedMaxReplyBytes bounds how much of a single memcached reply
// memcachedCmdLive will buffer. The read loop below only had a 2s connection
// deadline, no cap on bytes accumulated — a process squatting on 127.0.0.1:11211
// (or [::1]:11211) that answers the initial "version" probe to pass
// detectMemcached and then streams data as fast as loopback allows without ever
// sending the terminator could otherwise force an allocation on the order of
// gigabytes in a single strings.Builder within the 2s window. A real memcached
// "stats"/"stats settings" reply is a few KB; this is generously sized above
// that.
const memcachedMaxReplyBytes = 4 << 20 // 4MiB

// memcachedCmdLive dials addr, sends the memcached text command, and returns the
// response. For multi-line replies (stats) it reads until the "END" terminator;
// for a single-line reply (version) it returns the first line. Best-effort with a
// short deadline so it never hangs a health run. The accumulated reply is capped
// at memcachedMaxReplyBytes regardless of how long the deadline leaves to run —
// if the cap is hit before a terminator ever arrives, the read bails out rather
// than continuing to buffer (and re-scan) an ever-growing, uncapped response.
func memcachedCmdLive(ctx context.Context, network, addr, cmd string, untilEND bool) (string, bool) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return "", false
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(cmd + "\r\n")); err != nil {
		return "", false
	}
	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			if remaining := memcachedMaxReplyBytes - buf.Len(); remaining > 0 {
				if remaining < n {
					buf.Write(tmp[:remaining])
				} else {
					buf.Write(tmp[:n])
				}
			}
		}
		s := buf.String()
		if untilEND && strings.Contains(s, "\r\nEND\r\n") {
			break
		}
		if !untilEND && strings.Contains(s, "\r\n") {
			break
		}
		if err != nil {
			break
		}
		if buf.Len() >= memcachedMaxReplyBytes {
			break // cap reached without ever seeing a terminator — bail rather than spin to the deadline
		}
	}
	return buf.String(), buf.Len() > 0
}

// detectMemcached returns the (network, addr) of a local server that answers the
// memcached protocol with a VERSION line, plus the version. Confirms it's really
// memcached, not just any process on 11211; tries both loopback families.
func detectMemcached(ctx context.Context) (network, addr, version string) {
	for _, a := range []struct{ net, addr string }{
		{"tcp", "127.0.0.1:11211"},
		{"tcp", "[::1]:11211"},
	} {
		out, ok := memcachedCmd(ctx, a.net, a.addr, "version", false)
		if ok && strings.HasPrefix(out, "VERSION ") {
			v := strings.TrimSpace(strings.TrimPrefix(strings.SplitN(out, "\r\n", 2)[0], "VERSION "))
			return a.net, a.addr, v
		}
	}
	return "", "", ""
}

// MemcachedAvailable reports whether a local memcached server is answering.
func MemcachedAvailable() bool {
	_, addr, _ := detectMemcached(context.Background())
	return addr != ""
}

type MemcachedCollector struct{}

func NewMemcachedCollector() *MemcachedCollector { return &MemcachedCollector{} }

func (c *MemcachedCollector) Name() string           { return "Memcached" }
func (c *MemcachedCollector) Timeout() time.Duration { return 4 * time.Second }

func (c *MemcachedCollector) Collect(ctx context.Context) (interface{}, error) {
	network, addr, version := detectMemcached(ctx)
	if addr == "" {
		return &models.MemcachedInfo{Detected: false}, nil
	}
	info := &models.MemcachedInfo{Detected: true, Addr: addr, Version: version}

	stats, ok := memcachedCmd(ctx, network, addr, "stats", true)
	if !ok || !strings.Contains(stats, "STAT ") {
		info.StatusReason = "memcached stats unavailable"
		return info, nil
	}
	info.MetricsRead = true
	kv := parseMemcachedStats(stats)
	info.CurrConnections = atoiSafe(kv["curr_connections"])
	if mc := atoiSafe(kv["max_connections"]); mc > 0 {
		info.MaxConnections = mc
		info.MaxConnsRead = true
	}
	info.UsedBytes = atoi64(kv["bytes"])
	info.LimitMaxBytes = atoi64(kv["limit_maxbytes"])
	info.Evictions = atoi64(kv["evictions"])
	info.CurrItems = atoi64(kv["curr_items"])

	// memcached evicts to stay UNDER limit_maxbytes, so bytes/limit rarely shows
	// pressure — active eviction does. Sample evictions again after a short pause:
	// a rising count means it's evicting NOW (working set > cache), which a single
	// cumulative read can't distinguish from a long-ago blip.
	time.Sleep(400 * time.Millisecond)
	if stats2, ok := memcachedCmdSampled(ctx, network, addr, "stats", "stats#2", true); ok {
		if e2 := atoi64(parseMemcachedStats(stats2)["evictions"]); e2 > info.Evictions {
			info.EvictingNow = true
			info.Evictions = e2
		}
	}
	// max_connections isn't in plain "stats" on every build — fall back to settings.
	if !info.MaxConnsRead {
		if settings, ok := memcachedCmd(ctx, network, addr, "stats settings", true); ok {
			if mc := atoiSafe(parseMemcachedStats(settings)["maxconns"]); mc > 0 {
				info.MaxConnections = mc
				info.MaxConnsRead = true
			}
		}
	}
	return info, nil
}

// parseMemcachedStats parses "STAT <key> <value>" lines into a map.
func parseMemcachedStats(out string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) >= 3 && f[0] == "STAT" {
			kv[f[1]] = f[2]
		}
	}
	return kv
}
