//go:build linux

package collectors

// network_deep_extra_test.go — additional branch coverage for network_deep.go
// parseTCPCounters paths not reached by the existing test files.

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestParseTCPCounters_MissingNetstat guards the early-return path: when
// /proc/net/netstat is absent (readFile fails), parseTCPCounters must still
// parse sockstat and then return without panicking.
func TestParseTCPCounters_MissingNetstat(t *testing.T) {
	// Not parallel: withFixtureSource swaps the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/sockstat", []byte("TCP: inuse 5 orphan 0 tw 10 alloc 7 mem 2\n"))
		// /proc/net/netstat intentionally absent — must trigger the early return
	})
	info := &models.NetworkInfo{}
	parseTCPCounters(info)
	if info.TimeWaitCount != 10 {
		t.Errorf("TimeWaitCount = %d, want 10 (sockstat still parsed before netstat early-return)", info.TimeWaitCount)
	}
	if info.SynRetransCount != 0 || info.ListenOverflows != 0 || info.RetransFailCount != 0 {
		t.Errorf("TcpExt counters must be 0 when netstat is absent, got %+v", info)
	}
}

// TestParseTCPCounters_MismatchedHeaderValueLength guards the
// "len(headers) != len(values)" skip branch inside the TcpExt loop: when the
// header row and value row have different field counts the parser must skip
// that pair and not set any counters.
func TestParseTCPCounters_MismatchedHeaderValueLength(t *testing.T) {
	// Not parallel: withFixtureSource swaps the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		// Header has 3 fields, values row has 2 — mismatched, must be skipped.
		b.PutFile("/proc/net/netstat", []byte(
			"TcpExt: TCPSynRetrans ListenOverflows TCPRetransFail\n"+
				"TcpExt: 0 0\n", // only 2 value fields — mismatch
		))
	})
	info := &models.NetworkInfo{}
	parseTCPCounters(info)
	if info.SynRetransCount != 0 || info.ListenOverflows != 0 || info.RetransFailCount != 0 {
		t.Errorf("mismatched header/value lengths must result in zero counters, got %+v", info)
	}
}

// TestParseTCPCounters_NonTcpExtPrefixSkipped guards the "!HasPrefix TcpExt"
// continue branch: lines that don't start with "TcpExt:" must be silently
// skipped, and a following valid TcpExt pair is still parsed.
func TestParseTCPCounters_NonTcpExtPrefixSkipped(t *testing.T) {
	// Not parallel: withFixtureSource swaps the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/netstat", []byte(
			"IpExt: InNoRoutes InTruncatedPkts\n"+
				"IpExt: 1 2\n"+
				"TcpExt: TCPSynRetrans\n"+
				"TcpExt: 7\n",
		))
	})
	info := &models.NetworkInfo{}
	parseTCPCounters(info)
	if info.SynRetransCount != 7 {
		t.Errorf("SynRetransCount = %d, want 7 (IpExt lines must be skipped, TcpExt still parsed)", info.SynRetransCount)
	}
}

// TestParseTCPCounters_NoTwFieldInSockstat guards the sockstat parse branch
// when the TCP: line is present but has no "tw" field — TimeWaitCount must
// stay 0 (the inner loop finds no match and never calls Atoi).
func TestParseTCPCounters_NoTwFieldInSockstat(t *testing.T) {
	// Not parallel: withFixtureSource swaps the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/sockstat", []byte("TCP: inuse 5 orphan 0 alloc 7 mem 2\n"))
		b.PutFile("/proc/net/netstat", []byte("TcpExt: TCPSynRetrans\nTcpExt: 3\n"))
	})
	info := &models.NetworkInfo{}
	parseTCPCounters(info)
	if info.TimeWaitCount != 0 {
		t.Errorf("TimeWaitCount = %d, want 0 when 'tw' field absent from sockstat", info.TimeWaitCount)
	}
	if info.SynRetransCount != 3 {
		t.Errorf("SynRetransCount = %d, want 3 (netstat still parsed)", info.SynRetransCount)
	}
}

// TestParseTCPCounters_ConntrackZeroMax guards the "max > 0" guard: when
// nf_conntrack_max is 0 or unparseable ConntrackUsedPct must stay 0 to avoid
// a division-by-zero.
func TestParseTCPCounters_ConntrackZeroMax(t *testing.T) {
	// Not parallel: withFixtureSource swaps the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/net/netfilter/nf_conntrack_count", []byte("100\n"))
		b.PutFile("/proc/sys/net/netfilter/nf_conntrack_max", []byte("0\n"))
	})
	info := &models.NetworkInfo{}
	parseTCPCounters(info)
	if info.ConntrackUsedPct != 0 {
		t.Errorf("ConntrackUsedPct = %v, want 0 when max==0 (division guard)", info.ConntrackUsedPct)
	}
}
