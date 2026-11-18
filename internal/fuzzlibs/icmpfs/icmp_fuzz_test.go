// SPDX-License-Identifier: BSD-3-Clause

// Package icmpfs fuzzes the hostile-packet parsers in golang.org/x/net that
// DashDiag reaches when it parses ICMP replies through pro-bing: an on-path
// attacker or a spoofing host fully controls these bytes.
//
// Oracle: no panic, no hang. Crash-only parsers.
package icmpfs

import (
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	protoICMP   = 1
	protoICMPv6 = 58
)

// FuzzParseMessageV4 drives icmp.ParseMessage for IPv4 ICMP.
func FuzzParseMessageV4(f *testing.F) {
	f.Add([]byte{8, 0, 0, 0, 0, 1, 0, 1})  // echo request
	f.Add([]byte{0, 0, 0, 0, 0, 1, 0, 1})  // echo reply
	f.Add([]byte{3, 1, 0, 0, 0, 0, 0, 0})  // dest unreachable
	f.Add([]byte{11, 0, 0, 0, 0, 0, 0, 0}) // time exceeded
	f.Fuzz(func(t *testing.T, data []byte) {
		if m, err := icmp.ParseMessage(protoICMP, data); err == nil && m != nil {
			// Round-trip: a successfully parsed message should marshal back.
			_, _ = m.Body.Marshal(protoICMP)
		}
	})
}

// FuzzParseMessageV6 drives icmp.ParseMessage for IPv6 ICMP.
func FuzzParseMessageV6(f *testing.F) {
	f.Add([]byte{128, 0, 0, 0, 0, 1, 0, 1}) // echo request
	f.Add([]byte{129, 0, 0, 0, 0, 1, 0, 1}) // echo reply
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0})   // dest unreachable
	f.Fuzz(func(t *testing.T, data []byte) {
		if m, err := icmp.ParseMessage(protoICMPv6, data); err == nil && m != nil {
			_, _ = m.Body.Marshal(protoICMPv6)
		}
	})
}

// FuzzParseIPv4Header drives both icmp.ParseIPv4Header and ipv4.ParseHeader on
// the inner-header bytes carried by ICMP error replies.
func FuzzParseIPv4Header(f *testing.F) {
	f.Add([]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = icmp.ParseIPv4Header(data)
		_, _ = ipv4.ParseHeader(data)
	})
}

// FuzzParseIPv6Header drives ipv6.ParseHeader.
func FuzzParseIPv6Header(f *testing.F) {
	f.Add([]byte{0x60, 0, 0, 0, 0, 0, 58, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ipv6.ParseHeader(data)
	})
}
