package share

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// FuzzDecode fuzzes Decode against arbitrary attacker-supplied text — a
// customer-pasted "-----BEGIN DSD REPORT-----" block is the least trusted
// input this package handles (another party's terminal, another party's
// clipboard, relayed through a support channel dsd never controls). Two
// properties must hold for every input:
//
//   - Decode must never return a decompressed payload larger than
//     maxDecodedReportBytes (the gzip-bomb guard) without an accompanying
//     error.
//   - Re-encoding the fuzz bytes with Encode and decoding the result must
//     round-trip byte-for-byte: Decode must never silently corrupt or
//     truncate a blob it accepts without error.
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		"just some text, no report here",
		Encode([]byte(`{"verdict":"OK"}`)),
		Encode(nil),
		Encode([]byte(strings.Repeat("x", 5000))),
		beginMarker + "\n" + formatVersion + "\n!!!not base64!!!\n" + endMarker + "\n",
		beginMarker + "\nv999\nQUJD\n" + endMarker + "\n",
		beginMarker + "\n" + formatVersion + "\n" + endMarker + "\n",
		beginMarker + "\n" + endMarker + "\n",
		beginMarker + "\n" + formatVersion + "\n" + base64.StdEncoding.EncodeToString([]byte("not a gzip stream")) + "\n" + endMarker + "\n",
		beginMarker + "\n" + beginMarker + "\n" + formatVersion + "\n" + endMarker + "\n",
		beginMarker,
		strings.Repeat(beginMarker+"\n", 100),
		"> " + beginMarker + "\n> " + formatVersion + "\n> QUJD\n> " + endMarker,
		"Hi support,\n\n> " + strings.Join(strings.Split(strings.TrimRight(Encode([]byte("nested reply payload")), "\n"), "\n"), "\n> ") + "\n\nThanks!",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		out, err := Decode(raw)
		if err == nil && len(out) > maxDecodedReportBytes {
			t.Fatalf("Decode returned %d bytes, exceeding maxDecodedReportBytes (%d) without an error", len(out), maxDecodedReportBytes)
		}

		blob := Encode([]byte(raw))
		got, err := Decode(blob)
		if err != nil {
			t.Fatalf("Decode(Encode(%q)) failed to round-trip: %v", raw, err)
		}
		if !bytes.Equal(got, []byte(raw)) {
			t.Fatalf("Decode(Encode(p)) round-trip mismatch: got %d bytes, want %d bytes", len(got), len(raw))
		}
	})
}
