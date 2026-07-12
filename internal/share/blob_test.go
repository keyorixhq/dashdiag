package share

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	payload := []byte(`{"hostname":"web01","verdict":"CRIT","insights":[{"check":"Disk","level":"CRIT","message":"sda full"}]}`)
	blob := Encode(payload)

	if !strings.Contains(blob, beginMarker) || !strings.Contains(blob, endMarker) {
		t.Fatalf("blob missing markers:\n%s", blob)
	}
	got, err := Decode(blob)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("round-trip mismatch:\n got %s\nwant %s", got, payload)
	}
}

func TestEncodeCompresses(t *testing.T) {
	// A realistic, repetitive report should encode smaller than its raw size.
	payload := []byte(strings.Repeat(`{"check":"Disk","level":"WARN","message":"disk utilization high"}`, 50))
	blob := Encode(payload)
	if len(blob) >= len(payload) {
		t.Errorf("blob (%d) should be smaller than payload (%d) — gzip not helping", len(blob), len(payload))
	}
}

// A blob pasted into a chat/email reply (surrounding prose + "> " quote
// prefixes + blank lines) must still decode.
func TestDecodeToleratesSurroundingNoise(t *testing.T) {
	payload := []byte(`{"verdict":"OK"}`)
	blob := Encode(payload)

	var quoted strings.Builder
	quoted.WriteString("Hi support, here's the output you asked for:\n\n")
	for line := range strings.SplitSeq(strings.TrimRight(blob, "\n"), "\n") {
		quoted.WriteString("> " + line + "\n")
	}
	quoted.WriteString("\nThanks!\n")

	got, err := Decode(quoted.String())
	if err != nil {
		t.Fatalf("Decode (quoted): %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("quoted round-trip mismatch: got %s want %s", got, payload)
	}
}

func TestDecodeNoBlob(t *testing.T) {
	if _, err := Decode("just some text, no report here"); err != ErrNoBlob {
		t.Errorf("expected ErrNoBlob, got %v", err)
	}
}

func TestDecodeCorruptBase64(t *testing.T) {
	bad := beginMarker + "\n" + formatVersion + "\n!!!not base64!!!\n" + endMarker + "\n"
	if _, err := Decode(bad); err == nil {
		t.Error("expected error for corrupt base64, got nil")
	}
}

func TestDecodeTruncatedGzipCaught(t *testing.T) {
	payload := []byte(`{"verdict":"WARN","insights":[{"check":"a","message":"` + strings.Repeat("x", 500) + `"}]}`)
	blob := Encode(payload)
	lines := strings.Split(strings.TrimRight(blob, "\n"), "\n")
	// Drop a middle data line (markers + version intact) — gzip CRC must catch it.
	truncated := append([]string{lines[0], lines[1]}, lines[4:]...)
	if _, err := Decode(strings.Join(truncated, "\n")); err == nil {
		t.Error("expected gzip/CRC error for truncated blob, got nil")
	}
}

// TestDecodeTruncatedTailAfterValidHeaderCaught covers the io.ReadAll/CRC
// failure path specifically: unlike TestDecodeTruncatedGzipCaught (which
// truncates a highly-compressible payload so severely that even
// gzip.NewReader's header check fails), this uses incompressible data so the
// gzip stream spans multiple wrapped base64 lines. Dropping only the final
// line leaves a valid gzip magic/header (NewReader succeeds) but truncates
// the compressed data mid-stream, so the failure must surface from
// io.ReadAll's CRC/EOF check instead.
func TestDecodeTruncatedTailAfterValidHeaderCaught(t *testing.T) {
	t.Parallel()
	rnd := make([]byte, 4000)
	for i := range rnd {
		rnd[i] = byte((i*2654435761 + 17) % 251) // deterministic, low-compressibility filler
	}
	blob := Encode(rnd)
	lines := strings.Split(strings.TrimRight(blob, "\n"), "\n")
	if len(lines) < 6 {
		t.Fatalf("test payload didn't produce a multi-line blob (got %d lines) — need more data lines to truncate only the tail", len(lines))
	}
	// Keep BEGIN, version, and all but the last data line + END; drop the
	// final data line so the stream is truncated but the header remains intact.
	truncated := append(append([]string{}, lines[:len(lines)-2]...), lines[len(lines)-1])
	_, err := Decode(strings.Join(truncated, "\n"))
	if err == nil {
		t.Fatal("expected decompress/CRC error for tail-truncated blob, got nil")
	}
	if !strings.Contains(err.Error(), "decompress/CRC failed") {
		t.Errorf("expected decompress/CRC error, got %v", err)
	}
}

// TestDecodeValidBase64NotGzip covers the case where the base64 payload
// decodes cleanly but the resulting bytes are not a gzip stream at all
// (distinct from TestDecodeTruncatedGzipCaught, which is valid-gzip-header
// but truncated mid-stream / bad CRC).
func TestDecodeValidBase64NotGzip(t *testing.T) {
	t.Parallel()
	// "hello world" base64-encoded — valid base64, but not gzip magic bytes.
	notGzip := base64.StdEncoding.EncodeToString([]byte("hello world, not a gzip stream"))
	bad := beginMarker + "\n" + formatVersion + "\n" + notGzip + "\n" + endMarker + "\n"
	_, err := Decode(bad)
	if err == nil || !strings.Contains(err.Error(), "not valid gzip") {
		t.Errorf("expected 'not valid gzip' error, got %v", err)
	}
}

func TestDecodeUnsupportedVersion(t *testing.T) {
	bad := beginMarker + "\nv999\nQUJD\n" + endMarker + "\n"
	_, err := Decode(bad)
	if err == nil || !strings.Contains(err.Error(), "unsupported DSD REPORT format") {
		t.Errorf("expected unsupported-version error, got %v", err)
	}
}
