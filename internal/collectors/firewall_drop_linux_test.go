//go:build linux

package collectors

import (
	"reflect"
	"testing"
)

// Verbatim `iptables -t filter -nvL INPUT` from VMware Photon OS 5.0 — the default
// DROP ruleset (note the NUMERIC proto column: 0=all, 6=tcp). lo + established are
// dismissed; only dport 22 is an explicit accept.
const iptInputPhotonDefault = `Chain INPUT (policy DROP 686 packets, 24792 bytes)
 pkts bytes target     prot opt in     out     source               destination
  628 51933 ACCEPT     0    --  lo     *       0.0.0.0/0            0.0.0.0/0
16514  337M ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
   69  4140 ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22`

func TestParseIPTInputAccept_PhotonDefault(t *testing.T) {
	accepted, determinable := parseIPTInputAccept(iptInputPhotonDefault)
	if !determinable {
		t.Fatal("the default Photon ruleset is fully parseable → determinable")
	}
	if !accepted[22] || len(accepted) != 1 {
		t.Errorf("want only port 22 accepted, got %v", accepted)
	}
}

func TestParseIPTInputAccept_MultiportAndRange(t *testing.T) {
	const out = `Chain INPUT (policy DROP)
 pkts bytes target prot opt in out source destination
    0 0 ACCEPT tcp -- * * 0.0.0.0/0 0.0.0.0/0 multiport dports 80,443
    0 0 ACCEPT tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcp dpts:8000:8002`
	accepted, determinable := parseIPTInputAccept(out)
	if !determinable {
		t.Fatal("multiport + range are parseable")
	}
	for _, p := range []int{80, 443, 8000, 8001, 8002} {
		if !accepted[p] {
			t.Errorf("port %d should be accepted, got %v", p, accepted)
		}
	}
}

// A jump to a custom chain (fail2ban, firewalld, docker, …) means we can't follow
// where a packet may be accepted → indeterminable → caller must not flag anything.
func TestParseIPTInputAccept_CustomChainBails(t *testing.T) {
	const out = `Chain INPUT (policy DROP)
 pkts bytes target prot opt in out source destination
    0 0 ACCEPT tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:22
    0 0 f2b-sshd tcp -- * * 0.0.0.0/0 0.0.0.0/0 multiport dports 22`
	if _, determinable := parseIPTInputAccept(out); determinable {
		t.Error("a custom-chain jump must make the ruleset indeterminable")
	}
}

// A non-lo ACCEPT with no explicit dport (blanket accept / ipset / source-scoped)
// could permit arbitrary inbound → indeterminable.
func TestParseIPTInputAccept_BlanketAcceptBails(t *testing.T) {
	const out = `Chain INPUT (policy DROP)
 pkts bytes target prot opt in out source destination
    0 0 ACCEPT all -- * * 10.0.0.0/8 0.0.0.0/0`
	if _, determinable := parseIPTInputAccept(out); determinable {
		t.Error("a non-lo no-dport ACCEPT must make the ruleset indeterminable")
	}
}

func TestParseProcNetTCPListeners(t *testing.T) {
	// sl local_address rem_address st ... — 0A=LISTEN. 00000000:0016 = 0.0.0.0:22,
	// 0100007F:1F90 = 127.0.0.1:8080 (loopback, excluded), :8443 wildcard included.
	const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000
   2: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0
   3: 00000000:0050 0A0A0A0A:1234 01 00000000:00000000 00:00000000 00000000     0`
	got := parseProcNetTCPListeners(procTCP)
	want := []int{22, 0x20FB} // 0x16=22, 0x20FB=8443; 8080 is loopback; :80 is ESTABLISHED not LISTEN
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestIsAllZeroHexAddr(t *testing.T) {
	if !isAllZeroHexAddr("00000000") || !isAllZeroHexAddr("00000000000000000000000000000000") {
		t.Error("all-zero v4/v6 wildcard must be true")
	}
	if isAllZeroHexAddr("0100007F") || isAllZeroHexAddr("") {
		t.Error("loopback / empty must be false")
	}
}
