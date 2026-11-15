// SPDX-License-Identifier: BSD-3-Clause

// Package mcpfs fuzzes the JSON-RPC framing/decoding of
// github.com/modelcontextprotocol/go-sdk, which DashDiag's `dsd mcp` server
// (cmd/mcp.go) feeds with bytes from an untrusted MCP client over stdio.
//
// Oracles: no panic/hang on DecodeMessage; and a decode->encode->decode
// round-trip is stable (re-encoding a decoded message and decoding again
// yields an equal wire form).
package mcpfs

import (
	"bytes"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func FuzzDecodeMessage(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"notify","params":[1,2,3]}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":"x","error":{"code":-32600,"message":"bad"}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := jsonrpc.DecodeMessage(data)
		if err != nil || msg == nil {
			return
		}
		// Round-trip stability: a decoded message must re-encode, and the
		// re-encoded bytes must decode to something that encodes identically.
		enc1, err := jsonrpc.EncodeMessage(msg)
		if err != nil {
			t.Fatalf("decoded message failed to re-encode: %v", err)
		}
		msg2, err := jsonrpc.DecodeMessage(enc1)
		if err != nil {
			t.Fatalf("re-encoded message failed to decode: %v", err)
		}
		enc2, err := jsonrpc.EncodeMessage(msg2)
		if err != nil {
			t.Fatalf("second encode failed: %v", err)
		}
		if !bytes.Equal(enc1, enc2) {
			t.Fatalf("encode not idempotent:\n first: %s\nsecond: %s", enc1, enc2)
		}
	})
}
