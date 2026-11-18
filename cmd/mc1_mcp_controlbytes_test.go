package cmd

// MC3 finding F-MC3-1 — control-byte reflection through the go-sdk JSON encoder.
//
// A hostile tool-call argument that fails schema validation is quoted back by the
// SDK in its error message. Which control bytes survive that round-trip into the
// JSON-RPC output the client reads? This test pins the exact answer, so it is both
// the documentation of F-MC3-1 and a regression guard in two directions:
//
//   - LOAD-BEARING (security): ESC (0x1B) and C0 controls (BEL 0x07, NUL 0x00)
//     must NEVER appear raw — encoding/json escapes <0x20 to \u00XX, or the raw
//     byte makes the frame unparseable so nothing is reflected. If any of these
//     ever leak raw, that is a terminal-injection regression and this test fails.
//   - KNOWN GAP (reported HARDENING): U+007F (DEL) and the C1 range (U+009B CSI,
//     U+009D OSC) ARE reflected raw, because encoding/json does not escape them.
//     This is a Go-stdlib/go-sdk property reachable from a remote/confused MCP
//     peer, not a dsd code defect; DEL is benign and UTF-8 C1 is low threat on
//     modern terminals. If a future SDK/stdlib starts escaping them, this test
//     flips and we revisit the finding (and can re-tighten M3).
//
// The bytes are controlled by the MCP peer (the tool-call argument); the live
// production path is identical — `dsd mcp`'s real handlers sit BEHIND the same SDK
// schema-validation layer that generates and encodes this error.

import (
	"strings"
	"testing"
)

func TestMC3SDKReflectsControlsRaw(t *testing.T) {
	// deep is declared bool on dsd_health; a string value forces the SDK to emit a
	// validation error quoting the offending value — the reflection channel.
	mk := func(payload string) []byte {
		return append(mc1Handshake(),
			[]byte(`{"jsonrpc":"2.0","id":0,"method":"tools/call","params":{"name":"dsd_health","arguments":{"deep":"`+payload+`"}}}`+"\n")...)
	}
	cases := []struct {
		name     string
		payload  string // raw bytes placed inside the JSON string value
		r        rune   // the rune we check for in the output
		wantRaw  bool   // whether the raw rune is expected to survive into output
		security bool   // true => a raw leak here is a security regression
	}{
		{"ESC_U+001B", "\x1b", 0x1b, false, true},
		{"BEL_U+0007", "\x07", 0x07, false, true},
		{"NUL_U+0000", "\x00", 0x00, false, true},
		{"DEL_U+007F", "\x7f", 0x7f, true, false},
		{"CSI_U+009B", "\xc2\x9b", 0x9b, true, false},
		{"OSC_U+009D", "\xc2\x9d", 0x9d, true, false},
	}
	for _, c := range cases {
		out, _ := serveOnce(mk(c.payload))
		gotRaw := strings.ContainsRune(string(out), c.r)
		if gotRaw != c.wantRaw {
			if c.security && gotRaw {
				t.Fatalf("%s: SECURITY REGRESSION — raw control byte %U now leaks into MCP output: %q",
					c.name, c.r, clip(out))
			}
			t.Fatalf("%s: control-reflection behaviour changed: rawPresent=%v want=%v (revisit F-MC3-1): %q",
				c.name, gotRaw, c.wantRaw, clip(out))
		}
	}
}
