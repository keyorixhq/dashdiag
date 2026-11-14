package collectors

// probing_reply_repro_test.go — reproducers for the pro-bing findings, on the
// same fake-conn harness as FuzzProBingReplyAccounting (real pro-bing
// receive path, no socket).
//
// The red halves are gated behind DSD_NET1_REPRO=1 because they fail on the
// current dependency versions by design. The green halves always run: they
// show the same oracle does not fire on the defect-free variant of the input.
//
// What this does NOT verify: that an attacker can see the echo request (true
// for the ping target itself and anything on path, assumed, not simulated);
// DashDiag's verdict thresholds for the resulting RTT value.

import (
	"net"
	"os"
	"testing"
	"time"

	goping "github.com/prometheus-community/pro-bing"
)

const pbYear = 365 * 24 * time.Hour

func pbForged(target int, ts time.Time) pbOp {
	return pbOp{kind: 4, target: target, arg: uint64(ts.UnixNano())}
}

// NET1-F2: two forged payload timestamps whose RTTs differ by more than the
// int64 nanosecond range overflow `delta := pkt.Rtt - p.avgRtt` in pro-bing's
// updateStatistics; AvgRtt comes out with the wrong sign and magnitude.
func TestReproProBingAvgRttOverflow(t *testing.T) {
	if os.Getenv("DSD_NET1_REPRO") != "1" {
		t.Skip("red half of the NET1-F2 red/green proof; set DSD_NET1_REPRO=1 (fails on pro-bing v0.9.1)")
	}
	now := time.Now()
	pbCheckScenario(t, true, []pbOp{
		pbForged(0, now.Add(100*pbYear)),  // RTT ≈ -100 years
		pbForged(1, now.Add(-200*pbYear)), // RTT ≈ +200 years; delta ≈ 300y > MaxInt64 ns
	}, true)
}

func TestReproProBingAvgRttOverflow_NoOverflowGreen(t *testing.T) {
	now := time.Now()
	pbCheckScenario(t, true, []pbOp{
		pbForged(0, now.Add(50*pbYear)),
		pbForged(1, now.Add(-50*pbYear)),
	}, true)
}

// NET1-F3: one forged future timestamp yields a negative RTT, which pro-bing
// returns as AvgRtt and tryOnePing turns into a negative latency in ms with
// loss 0% — a "faster than light" gateway/internet ping that DashDiag
// reports as healthy. Oracle: the latency tryOnePing would return is >= 0.
func TestReproProBingNegativeRTT(t *testing.T) {
	if os.Getenv("DSD_NET1_REPRO") != "1" {
		t.Skip("red half of the NET1-F3 red/green proof; set DSD_NET1_REPRO=1 (fails on pro-bing v0.9.1)")
	}
	ms := pbAvgMsFor(t, time.Now().Add(5*time.Second))
	if ms < 0 {
		t.Errorf("tryOnePing would report avg RTT %.1f ms from a single forged echo reply", ms)
	}
}

func TestReproProBingNegativeRTT_HonestTimestampGreen(t *testing.T) {
	if ms := pbAvgMsFor(t, time.Time{}); ms < 0 {
		t.Fatalf("honest reply produced negative RTT %.3f ms — harness bug", ms)
	}
}

// pbAvgMsFor runs one ping whose only reply carries forgedTS (zero: echo the
// request's own timestamp) and returns avg RTT in ms exactly as tryOnePing
// computes it from Statistics().
func pbAvgMsFor(t *testing.T, forgedTS time.Time) float64 {
	t.Helper()
	op := pbOp{kind: 0, target: 0}
	if !forgedTS.IsZero() {
		op = pbForged(0, forgedTS)
	}
	conn := &pbFakeConn{wrote: make(chan struct{}, 1), ops: []pbOp{op}, fenceSeen: make(chan struct{}), rawTS: true}
	// No fence: end the run on Count, the way tryOnePing configures it.
	conn.fenceSent = true
	p := goping.New(pbTarget.String())
	p.SetLogger(goping.NoopLogger{})
	p.SetIPAddr(&net.IPAddr{IP: pbTarget})
	p.SetPrivileged(true)
	p.Count = 1
	p.Interval = time.Millisecond
	p.Timeout = 2 * time.Second
	done := make(chan error, 1)
	go func() { done <- probingRun(p, t.Context(), conn) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pro-bing run did not finish")
	}
	close(conn.fenceSeen)
	st := p.Statistics()
	if st.PacketsRecv != 1 {
		t.Fatalf("premise: expected the single reply to be counted, recv=%d", st.PacketsRecv)
	}
	return float64(st.AvgRtt) / float64(time.Millisecond)
}
