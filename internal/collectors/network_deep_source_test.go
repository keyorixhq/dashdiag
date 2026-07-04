//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestParseTCPCounters guards the deep TCP-counter parser — the project's most
// bug-prone diagnostic area (TIME_WAIT / SYN-retrans / listen-overflow /
// conntrack, per the #686/#687 wiring history). All five inputs are separate
// /proc files, each independently optional.
func TestParseTCPCounters(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/sockstat", []byte("sockets: used 300\nTCP: inuse 12 orphan 0 tw 542 alloc 20 mem 10\n"))
		b.PutFile("/proc/net/netstat", []byte(
			"TcpExt: SyncookiesSent TCPSynRetrans ListenOverflows TCPRetransFail\n"+
				"TcpExt: 0 37 4 2\n",
		))
		b.PutFile("/proc/uptime", []byte("123456.78 98765.43\n"))
		b.PutFile("/proc/sys/net/netfilter/nf_conntrack_count", []byte("6000\n"))
		b.PutFile("/proc/sys/net/netfilter/nf_conntrack_max", []byte("10000\n"))
	})
	info := &models.NetworkInfo{}
	parseTCPCounters(info)

	if info.TimeWaitCount != 542 {
		t.Errorf("TIME_WAIT count should be parsed from sockstat, got %d", info.TimeWaitCount)
	}
	if info.SynRetransCount != 37 || info.ListenOverflows != 4 || info.RetransFailCount != 2 {
		t.Errorf("TcpExt counters should be parsed by column name (header/value row alignment), got %+v", info)
	}
	if info.UptimeSec != 123456.78 {
		t.Errorf("uptime should be parsed from the first field, got %v", info.UptimeSec)
	}
	if info.ConntrackUsedPct != 60 {
		t.Errorf("conntrack used pct should be count/max*100 = 60, got %v", info.ConntrackUsedPct)
	}
}

// TestParseTCPCountersMissingConntrack guards the "module not loaded" case:
// without both nf_conntrack files present, ConntrackUsedPct must stay 0, not
// divide-by-zero or read a partial value.
func TestParseTCPCountersMissingConntrack(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/netstat", []byte("TcpExt: TCPSynRetrans\nTcpExt: 5\n"))
	})
	info := &models.NetworkInfo{}
	parseTCPCounters(info)
	if info.ConntrackUsedPct != 0 {
		t.Errorf("without nf_conntrack files, ConntrackUsedPct must stay 0, got %v", info.ConntrackUsedPct)
	}
	if info.SynRetransCount != 5 {
		t.Errorf("the present netstat data should still be parsed, got %+v", info)
	}
}
