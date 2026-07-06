//go:build linux

package collectors

import "testing"

// FuzzParseIPTInputAccept fuzzes the `iptables -nvL INPUT` parser feeding the
// firewall "exposed ports" verdict. Complex, multi-line, stateful parsing of
// real external-tool output (THREAT_MODEL_CLI.md §5) — unlike the hand-picked
// TestParseIPTInputAccept_* cases, this explores field-count/whitespace/target
// combinations nobody thought to write as an example. Invariant: never panic,
// on arbitrary/garbled input.
func FuzzParseIPTInputAccept(f *testing.F) {
	f.Add(iptInputPhotonDefault)
	seeds := []string{
		"Chain INPUT (policy DROP)\n pkts bytes target prot opt in out source destination\n    0 0 ACCEPT tcp -- * * 0.0.0.0/0 0.0.0.0/0 multiport dports 80,443",
		"Chain INPUT (policy DROP)\n    0 0 ACCEPT tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcp dpts:8000:8002",
		"Chain INPUT (policy ACCEPT)",
		"",
		"garbage\nmore garbage",
		"Chain INPUT (policy DROP)\n0 0 ACCEPT", // too few fields
		"Chain INPUT (policy DROP)\n0 0 CUSTOM_CHAIN_JUMP tcp -- * * 0.0.0.0/0 0.0.0.0/0",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, out string) {
		_, _ = parseIPTInputAccept(out)
	})
}

// FuzzParseNFTInputAccept fuzzes the `nft list ruleset` parser — the nftables
// counterpart to FuzzParseIPTInputAccept, same rationale (THREAT_MODEL_CLI.md
// §5). Invariant: never panic on arbitrary/garbled ruleset text.
func FuzzParseNFTInputAccept(f *testing.F) {
	f.Add(nftInputClean)
	seeds := []string{
		"table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}",
		"chain input {", // truncated, no closing brace
		"type filter hook input priority filter; policy drop;",
		"",
		"garbage { not a real ruleset",
		"table inet filter {\n\tchain input {\n\t\ttcp dport { 80, 443, } accept\n\t}\n}", // trailing comma in set
		"table inet filter {\n\tchain input {\n\t\tjump some_chain\n\t}\n}",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, ruleset string) {
		_, _ = parseNFTInputAccept(ruleset)
	})
}

// FuzzParseProcNetTCPListeners fuzzes the /proc/net/tcp{,6} hex-field parser
// feeding the same firewall verdict. Input is a pseudo-file, not a command,
// but still kernel-formatted external data outside this process's control.
func FuzzParseProcNetTCPListeners(f *testing.F) {
	seeds := []string{
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0",
		"",
		"garbage line\nmore garbage",
		"0: not:hex 00000000:0000 0A",
		"0: 00000000:GGGG 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1 0",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		_ = parseProcNetTCPListeners(data)
	})
}
