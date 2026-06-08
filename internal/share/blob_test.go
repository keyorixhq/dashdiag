package share

import (
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
	for _, line := range strings.Split(strings.TrimRight(blob, "\n"), "\n") {
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

func TestDecodeUnsupportedVersion(t *testing.T) {
	bad := beginMarker + "\nv999\nQUJD\n" + endMarker + "\n"
	_, err := Decode(bad)
	if err == nil || !strings.Contains(err.Error(), "unsupported DSD REPORT format") {
		t.Errorf("expected unsupported-version error, got %v", err)
	}
}
