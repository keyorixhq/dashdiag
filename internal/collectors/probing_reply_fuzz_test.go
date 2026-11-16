package collectors

// probing_reply_fuzz_test.go — FuzzProBingReplyAccounting drives the REAL
// prometheus-community/pro-bing receive path (recvICMP -> processPacket ->
// updateStatistics -> Statistics, the exact chain tryOnePing reads
// PacketsRecv/AvgRtt/PacketLoss from) with fuzzer-controlled ICMP replies.
//
// Who controls the bytes: every ICMP echo reply tryOnePing counts comes off
// the network. The ping target (the default gateway, 8.8.8.8) and anything
// on path sees the echo request — including pro-bing's tracker UUID and its
// send timestamp — so it can forge a reply that pro-bing will accept.
//
// pro-bing has no injectable connection, so the harness reaches the
// unexported (*Pinger).run through go:linkname and hands it a fake
// packetConn (an interface whose method names are all exported, so a type
// in this package satisfies it structurally). Nothing is listened on, no
// socket is opened.
//
// Oracle: an independent reply model. Every reply the fake conn delivers is
// decoded by the harness's own ICMP echo decoder (not golang.org/x/net/icmp)
// and judged against the requests the fake conn actually saw written:
// echo-reply type, ID match (per-GOOS/privilege rule documented below),
// tracker UUID match, sequence outstanding vs. already answered. The model's
// expected PacketsRecv / PacketsRecvDuplicates must equal Statistics(), and:
//   - PacketsSent equals the number of WriteTo calls;
//   - len(Rtts) == PacketsRecv; MinRtt/MaxRtt are the exact min/max of Rtts;
//   - AvgRtt is the arithmetic mean of Rtts within PacketsRecv nanoseconds
//     (Welford with integer Duration division truncates <1ns per step), with
//     the mean computed in big.Int so it cannot overflow;
//   - 0 <= PacketLoss <= 100 and equals (sent-recv)/sent*100;
//   - each counted reply's Rtt lies in [deliver - ts, seen - ts], where ts is
//     the timestamp the harness itself put into the reply payload — i.e. the
//     RTT is exactly "receive time minus payload timestamp" and nothing else.
//
// End of run is deterministic: after the scripted replies, the fake conn
// answers one fresh request (the fence) validly and waits for OnRecv to see
// it; replies are FIFO through a single consumer, so every scripted reply
// has been processed by then.
//
// What this does NOT verify: the real kernel/socket layer (x/net icmp
// ListenPacket, InstallICMPIDFilter, SetSource binding); IPv6 targets; the
// Count-based early stop (Count is -1 here so the fence is always reached);
// sequence-number wrap past 65535 (new tracker UUID); that an RTT derived
// from a forged payload timestamp is plausible — pro-bing trusts the echoed
// timestamp by design, so a forged one yields a negative or absurd RTT; that
// is reported as NET1-F3 with its own reproducer, not asserted here; and
// DashDiag's sysPing path (Linux prefers /bin/ping; pro-bing is the macOS
// path and the Linux no-ping-binary fallback).

import (
	"context"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
	_ "unsafe" // go:linkname

	goping "github.com/prometheus-community/pro-bing"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// probingPacketConn mirrors pro-bing's unexported packetConn method set.
type probingPacketConn interface {
	Close() error
	ICMPRequestType() icmp.Type
	ReadFrom(b []byte) (n int, ttl int, src net.Addr, err error)
	SetFlagTTL() error
	SetReadDeadline(t time.Time) error
	WriteTo(b []byte, dst net.Addr) (int, error)
	SetTTL(ttl int)
	SetMark(m uint) error
	SetDoNotFragment() error
	SetBroadcastFlag() error
	SetIfIndex(ifIndex int)
	SetSource(source net.IP)
	SetTrafficClass(uint8) error
	InstallICMPIDFilter(id int) error
}

//go:linkname probingRun github.com/prometheus-community/pro-bing.(*Pinger).run
func probingRun(p *goping.Pinger, ctx context.Context, conn probingPacketConn) error

const (
	pbTimeSliceLen = 8
	pbTrackerLen   = 16
	pbPayloadLen   = pbTimeSliceLen + pbTrackerLen // pro-bing's default Size
)

var pbTarget = net.IPv4(192, 0, 2, 1) // TEST-NET-1, never routed

type pbRequest struct {
	id, seq int
	data    []byte
}

type pbDelivery struct {
	wire      []byte // bytes the fake conn handed to ReadFrom (before truncation)
	n         int
	bufLen    int
	deliverAt time.Time
	ts        time.Time // timestamp the harness wrote into the payload, if any
}

// pbOp is one scripted reply: kind selects how it is derived from request
// target; arg/raw parameterise it.
type pbOp struct {
	kind   uint8
	target int
	arg    uint64
	raw    []byte
}

type pbFakeConn struct {
	mu       sync.Mutex
	reqs     []pbRequest
	wrote    chan struct{}
	deadline time.Time

	ops        []pbOp
	next       int
	unprivDarw bool // darwin + unprivileged ipv4: kernel prepends the IPv4 header
	rawTS      bool // forged timestamps verbatim (reproducers only)

	fenceSeq   int
	fenceSent  bool
	fenceSeen  chan struct{}
	deliveries []pbDelivery
}

func (c *pbFakeConn) Close() error                  { return nil }
func (c *pbFakeConn) ICMPRequestType() icmp.Type    { return ipv4.ICMPTypeEcho }
func (c *pbFakeConn) SetFlagTTL() error             { return nil }
func (c *pbFakeConn) SetTTL(int)                    {}
func (c *pbFakeConn) SetMark(uint) error            { return nil }
func (c *pbFakeConn) SetDoNotFragment() error       { return nil }
func (c *pbFakeConn) SetBroadcastFlag() error       { return nil }
func (c *pbFakeConn) SetIfIndex(int)                {}
func (c *pbFakeConn) SetSource(net.IP)              {}
func (c *pbFakeConn) SetTrafficClass(uint8) error   { return nil }
func (c *pbFakeConn) InstallICMPIDFilter(int) error { return nil }
func (c *pbFakeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *pbFakeConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	// Harness-side decode of the request (pro-bing marshals it with x/net).
	if len(b) < 8 || b[0] != 8 {
		return 0, errors.New("fake conn: unexpected request bytes")
	}
	r := pbRequest{
		id:   int(binary.BigEndian.Uint16(b[4:6])),
		seq:  int(binary.BigEndian.Uint16(b[6:8])),
		data: append([]byte(nil), b[8:]...),
	}
	c.mu.Lock()
	c.reqs = append(c.reqs, r)
	c.mu.Unlock()
	select {
	case c.wrote <- struct{}{}:
	default:
	}
	return len(b), nil
}

type pbTimeoutErr struct{}

func (pbTimeoutErr) Error() string   { return "i/o timeout" }
func (pbTimeoutErr) Timeout() bool   { return true }
func (pbTimeoutErr) Temporary() bool { return true }

var errPBScriptDone = errors.New("fake conn: script done")

func pbEchoReply(id, seq int, data []byte) []byte {
	out := make([]byte, 8+len(data))
	out[0] = 0 // echo reply
	binary.BigEndian.PutUint16(out[4:6], uint16(id))
	binary.BigEndian.PutUint16(out[6:8], uint16(seq))
	copy(out[8:], data)
	return out
}

// build materialises op against the requests seen so far; ok=false means
// its target request has not been written yet.
func (c *pbFakeConn) build(op pbOp) (wire []byte, ts time.Time, ok bool) {
	if op.kind%8 == 7 {
		return op.raw, time.Time{}, true
	}
	if op.target >= len(c.reqs) {
		return nil, time.Time{}, false
	}
	r := c.reqs[op.target]
	data := append([]byte(nil), r.data...)
	id, seq := r.id, r.seq
	switch op.kind % 8 {
	case 2: // foreign ICMP ID
		id ^= int(op.arg&0xffff) | 1
	case 3: // corrupt one tracker-UUID byte
		if len(data) >= pbPayloadLen {
			data[pbTimeSliceLen+int(op.arg%pbTrackerLen)] ^= byte(op.arg>>8) | 1
		}
	case 4: // forged send timestamp
		// Bounded to now ± 2^61 ns (~73 years): beyond that, two counted
		// RTTs can differ by more than int64 nanoseconds and pro-bing's
		// Welford update overflows — the already-reproduced NET1-F2
		// (TestReproProBingAvgRttOverflow). Fuzzing past it would only
		// rediscover F2; the assertions are unchanged.
		switch {
		case len(data) < pbTimeSliceLen:
		case c.rawTS:
			binary.BigEndian.PutUint64(data[:8], op.arg)
		default:
			binary.BigEndian.PutUint64(data[:8], uint64(time.Now().UnixNano()+int64(op.arg)>>2))
		}
	case 5: // truncated payload
		data = data[:int(op.arg%uint64(len(data)+1))]
	case 6: // another request's seq, or one this run can never send
		// A seq not yet sent at delivery time but sent before pro-bing
		// processes the reply (the recv channel is buffered) has a racy
		// outcome, so the fixture only forges deterministic ones: an
		// already-written request's seq, or >= 60000 (at Interval=1ms within
		// the 6s bound at most ~6000 requests are ever sent).
		// Never the fence's request: that one must stay unanswered until
		// the fence itself is delivered.
		if op.arg&1 == 0 {
			pool := min(len(c.reqs), c.fenceIndex())
			seq = c.reqs[int(op.arg>>1%uint64(pool))].seq
		} else {
			seq = 60000 + int(op.arg>>1%5535)
		}
	}
	wire = pbEchoReply(id, seq, data)
	if op.kind%8 == 6 && op.arg>>16&1 == 1 {
		wire[0] = byte(op.arg >> 24) // arbitrary ICMP type
	}
	if len(data) >= pbTimeSliceLen {
		ts = time.Unix(0, int64(binary.BigEndian.Uint64(data[:8])))
	}
	return wire, ts, true
}

func (c *pbFakeConn) ReadFrom(b []byte) (int, int, net.Addr, error) {
	for {
		c.mu.Lock()
		var wire []byte
		var ts time.Time
		ready := false
		fence := false
		switch {
		case c.next < len(c.ops):
			wire, ts, ready = c.build(c.ops[c.next])
			if ready {
				c.next++
			}
		case !c.fenceSent:
			// The fence answers the first request no op could target.
			if fi := c.fenceIndex(); fi < len(c.reqs) {
				r := c.reqs[fi]
				wire = pbEchoReply(r.id, r.seq, r.data)
				ts = time.Unix(0, int64(binary.BigEndian.Uint64(r.data[:8])))
				c.fenceSeq = r.seq
				c.fenceSent = true
				ready, fence = true, true
			}
		default:
			c.mu.Unlock()
			select {
			case <-c.fenceSeen:
				return 0, 0, nil, errPBScriptDone
			case <-time.After(5 * time.Millisecond):
				return 0, 0, nil, &net.OpError{Op: "read", Err: pbTimeoutErr{}}
			}
		}
		deadline := c.deadline
		c.mu.Unlock()

		if ready {
			if c.unprivDarw {
				hdr := make([]byte, ipv4.HeaderLen, ipv4.HeaderLen+len(wire))
				hdr[0] = 0x45
				wire = append(hdr, wire...)
			}
			n := copy(b, wire)
			c.mu.Lock()
			c.deliveries = append(c.deliveries, pbDelivery{wire: wire, n: n, bufLen: len(b), deliverAt: time.Now(), ts: ts})
			c.mu.Unlock()
			_ = fence
			return n, 64, &net.IPAddr{IP: pbTarget}, nil
		}
		wait := time.Until(deadline)
		if wait <= 0 {
			return 0, 0, nil, &net.OpError{Op: "read", Err: pbTimeoutErr{}}
		}
		select {
		case <-c.wrote:
		case <-time.After(wait):
		}
	}
}

func (c *pbFakeConn) fenceIndex() int {
	maxT := -1
	for _, op := range c.ops {
		if op.kind%8 != 7 && op.target > maxT {
			maxT = op.target
		}
	}
	return maxT + 1
}

// pbDecodeOps turns fuzz bytes into at most 12 scripted replies.
func pbDecodeOps(prog []byte) []pbOp {
	var ops []pbOp
	for len(prog) >= 2 && len(ops) < 12 {
		kind, target := prog[0], int(prog[1]%4)
		prog = prog[2:]
		var arg uint64
		if len(prog) >= 8 {
			arg = binary.BigEndian.Uint64(prog[:8])
			prog = prog[8:]
		} else {
			for _, x := range prog {
				arg = arg<<8 | uint64(x)
			}
			prog = nil
		}
		op := pbOp{kind: kind, target: target, arg: arg}
		if kind%8 == 7 {
			l := int(arg % 64)
			l = min(l, len(prog))
			op.raw = append([]byte(nil), prog[:l]...)
			prog = prog[l:]
		}
		ops = append(ops, op)
	}
	return ops
}

// pbModel is the independent judgement of one delivered reply.
type pbModel struct {
	recv, dups int
	counted    []pbDelivery
}

// pbIDMatches documents pro-bing's ID rule: on Linux an unprivileged (UDP)
// ICMP socket gets its ID rewritten by the kernel, so any ID is accepted;
// everywhere else, and for privileged raw sockets, the ID must match.
func pbIDMatches(privileged bool, got, want int) bool {
	if runtime.GOOS == "linux" && !privileged {
		return true
	}
	return got == want
}

func pbRunModel(privileged bool, reqs []pbRequest, deliveries []pbDelivery) pbModel {
	var m pbModel
	outstanding := map[int]bool{}
	for _, r := range reqs {
		outstanding[r.seq] = true
	}
	var tracker []byte
	var pid int
	if len(reqs) > 0 {
		tracker = reqs[0].data[pbTimeSliceLen:pbPayloadLen]
		pid = reqs[0].id
	}
	for _, d := range deliveries {
		buf := make([]byte, d.bufLen)
		copy(buf, d.wire[:d.n])
		// RFC 791 header strip, in place, as a raw IPv4 socket delivers it.
		if len(buf) >= ipv4.HeaderLen && buf[0]>>4 == 4 {
			if ihl := int(buf[0]&0x0f) * 4; ihl >= ipv4.HeaderLen && ihl <= len(buf) {
				copy(buf, buf[ihl:])
			}
		}
		if len(buf) < 8 || buf[0] != 0 { // not an echo reply
			continue
		}
		id := int(binary.BigEndian.Uint16(buf[4:6]))
		seq := int(binary.BigEndian.Uint16(buf[6:8]))
		data := buf[8:]
		if !pbIDMatches(privileged, id, pid) || len(data) < pbPayloadLen {
			continue
		}
		if string(data[pbTimeSliceLen:pbPayloadLen]) != string(tracker) {
			continue
		}
		if !outstanding[seq] {
			m.dups++
			continue
		}
		delete(outstanding, seq)
		m.recv++
		m.counted = append(m.counted, d)
	}
	return m
}

func FuzzProBingReplyAccounting(f *testing.F) {
	valid := func(target byte) []byte { return []byte{0, target} }
	f.Add(true, append(valid(0), valid(1)...))
	f.Add(true, append(valid(0), valid(0)...))           // duplicate
	f.Add(true, []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 7})    // foreign ID
	f.Add(true, []byte{3, 1, 0, 0, 0, 0, 0, 0, 0x55, 3}) // bad UUID
	f.Add(true, []byte{5, 0, 0, 0, 0, 0, 0, 0, 0, 10})   // truncated
	f.Add(true, []byte{6, 2, 0, 0, 0, 0, 0, 1, 0, 9})    // wrong type
	f.Add(true, []byte{6, 2, 0, 0, 0, 0, 0, 0, 0, 9})    // wrong seq
	f.Add(false, append(valid(0), []byte{7, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0x45, 0, 0, 0}...))
	f.Add(false, append(valid(3), valid(2)...))
	now := uint64(time.Now().UnixNano())
	ts := binary.BigEndian.AppendUint64(nil, now-uint64(time.Millisecond))
	f.Add(true, append([]byte{4, 0}, ts...))

	f.Fuzz(func(t *testing.T, privileged bool, prog []byte) {
		pbCheckScenario(t, privileged, pbDecodeOps(prog), false)
	})
}

// pbCheckScenario runs pro-bing against one reply script and applies every
// oracle listed in the file comment.
func pbCheckScenario(t *testing.T, privileged bool, ops []pbOp, rawTS bool) {
	t.Helper()
	{
		conn := &pbFakeConn{
			wrote:      make(chan struct{}, 1),
			ops:        ops,
			fenceSeen:  make(chan struct{}),
			unprivDarw: runtime.GOOS == "darwin" && !privileged,
			rawTS:      rawTS,
		}
		p := goping.New(pbTarget.String())
		p.SetLogger(goping.NoopLogger{})
		p.SetIPAddr(&net.IPAddr{IP: pbTarget})
		p.SetPrivileged(privileged)
		p.Count = -1
		p.Interval = time.Millisecond
		p.Timeout = 10 * time.Second // backstop only; the fence ends the run

		var mu sync.Mutex
		type seenPkt struct {
			seq int
			rtt time.Duration
			at  time.Time
		}
		var seen []seenPkt
		var fenceOnce sync.Once
		p.OnRecv = func(pkt *goping.Packet) {
			mu.Lock()
			seen = append(seen, seenPkt{seq: pkt.Seq, rtt: pkt.Rtt, at: time.Now()})
			mu.Unlock()
			conn.mu.Lock()
			isFence := conn.fenceSent && pkt.Seq == conn.fenceSeq
			conn.mu.Unlock()
			if isFence {
				fenceOnce.Do(func() { close(conn.fenceSeen) })
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		errCh := make(chan error, 1)
		go func() { errCh <- probingRun(p, ctx, conn) }()
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, errPBScriptDone) {
				t.Fatalf("run: unexpected error %v", err)
			}
		case <-time.After(6 * time.Second):
			t.Fatalf("bounded work: pro-bing run did not finish within 6s (%d ops)", len(ops))
		}
		select {
		case <-conn.fenceSeen:
		default:
			t.Fatalf("liveness: the fence reply (valid, fresh sequence) was never counted; ops=%+v", ops)
		}

		conn.mu.Lock()
		reqs := append([]pbRequest(nil), conn.reqs...)
		deliveries := append([]pbDelivery(nil), conn.deliveries...)
		conn.mu.Unlock()
		st := p.Statistics()
		model := pbRunModel(privileged, reqs, deliveries)

		if st.PacketsSent != len(reqs) {
			t.Fatalf("PacketsSent=%d but %d requests were written", st.PacketsSent, len(reqs))
		}
		if st.PacketsRecv != model.recv || st.PacketsRecvDuplicates != model.dups {
			t.Fatalf("accounting: pro-bing recv=%d dups=%d, model recv=%d dups=%d (ops=%+v)",
				st.PacketsRecv, st.PacketsRecvDuplicates, model.recv, model.dups, ops)
		}
		if st.PacketLoss < 0 || st.PacketLoss > 100 {
			t.Fatalf("PacketLoss=%v outside [0,100]", st.PacketLoss)
		}
		if want := float64(st.PacketsSent-st.PacketsRecv) / float64(st.PacketsSent) * 100; st.PacketLoss != want {
			t.Fatalf("PacketLoss=%v, want %v", st.PacketLoss, want)
		}
		if len(st.Rtts) != st.PacketsRecv {
			t.Fatalf("len(Rtts)=%d != PacketsRecv=%d", len(st.Rtts), st.PacketsRecv)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(seen) != len(model.counted) {
			t.Fatalf("OnRecv fired %d times, model counted %d", len(seen), len(model.counted))
		}
		sum := new(big.Int)
		for i, r := range st.Rtts {
			if r != seen[i].rtt {
				t.Fatalf("Rtts[%d]=%v but OnRecv reported %v", i, r, seen[i].rtt)
			}
			d := model.counted[i]
			lo, hi := d.deliverAt.Sub(d.ts), seen[i].at.Sub(d.ts)
			if r < lo || r > hi {
				t.Fatalf("Rtt[%d]=%v outside [%v, %v] = [deliver, seen] minus payload timestamp %v", i, r, lo, hi, d.ts)
			}
			if r < st.MinRtt || r > st.MaxRtt {
				t.Fatalf("Rtt %v outside [MinRtt %v, MaxRtt %v]", r, st.MinRtt, st.MaxRtt)
			}
			sum.Add(sum, big.NewInt(int64(r)))
		}
		if n := len(st.Rtts); n > 0 {
			mn, mx := st.Rtts[0], st.Rtts[0]
			for _, r := range st.Rtts {
				mn, mx = min(mn, r), max(mx, r)
			}
			if mn != st.MinRtt || mx != st.MaxRtt {
				t.Fatalf("MinRtt/MaxRtt=%v/%v, exact %v/%v", st.MinRtt, st.MaxRtt, mn, mx)
			}
			mean := new(big.Int).Quo(sum, big.NewInt(int64(n)))
			diff := new(big.Int).Sub(mean, big.NewInt(int64(st.AvgRtt)))
			if diff.Abs(diff).Cmp(big.NewInt(int64(n)+1)) > 0 {
				t.Fatalf("AvgRtt=%v, exact mean of %v is %v ns (|diff| %v ns > %d)", st.AvgRtt, st.Rtts, mean, diff, n+1)
			}
		}
	}
}
