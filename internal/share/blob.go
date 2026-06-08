// Package share implements the network-optional local "share blob": a compact,
// copy-pasteable encoding of a dsd report (the `dsd health --json` document).
//
// It is the local-first alternative to `--share` for the support-offload flow
// (ADR-0002 Decision 6): when a customer's VM has a broken network, they cannot
// upload a report or even reach an installer. `dsd health --blob` emits a
// self-contained text block they paste into their own support channel (from a
// working browser/laptop, not the broken VM); support runs `dsd decode` to turn
// it back into a readable diagnosis. No backend, no network, no prerequisites.
package share

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	beginMarker = "-----BEGIN DSD REPORT-----"
	endMarker   = "-----END DSD REPORT-----"
	// formatVersion is the first line inside the block. Bumping it lets a future
	// dsd evolve the payload while older binaries fail with a clear message
	// rather than mis-decoding.
	formatVersion = "v1"
	wrapCols      = 76 // line width — keeps the block readable and email-safe
)

// ErrNoBlob is returned when the input contains no DSD REPORT block.
var ErrNoBlob = errors.New("no DSD REPORT block found (expected text between the BEGIN/END markers)")

// Encode compresses and base64-encodes a report payload into a delimited,
// copy-pasteable text block. The payload is the raw `dsd health --json` bytes.
func Encode(payload []byte) string {
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	_, _ = zw.Write(payload)
	_ = zw.Close()
	b64 := base64.StdEncoding.EncodeToString(gz.Bytes())

	var sb strings.Builder
	sb.WriteString(beginMarker + "\n")
	sb.WriteString(formatVersion + "\n")
	for i := 0; i < len(b64); i += wrapCols {
		end := i + wrapCols
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end] + "\n")
	}
	sb.WriteString(endMarker + "\n")
	return sb.String()
}

// Decode extracts the first DSD REPORT block from text (which may be surrounded
// by chat/email noise and quote prefixes) and returns the original report
// bytes. The gzip CRC catches truncation or corruption from a bad copy-paste.
func Decode(text string) ([]byte, error) {
	var b64 strings.Builder
	inBlock, sawVersion, found := false, false, false

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(stripQuote(raw))
		switch {
		case strings.Contains(line, beginMarker):
			inBlock, sawVersion, found = true, false, true
			b64.Reset()
			continue
		case strings.Contains(line, endMarker):
			if inBlock {
				inBlock = false
			}
			continue
		}
		if !inBlock || line == "" {
			continue
		}
		if !sawVersion {
			sawVersion = true
			if line != formatVersion {
				return nil, fmt.Errorf("unsupported DSD REPORT format %q (this dsd understands %s) — update dsd to decode it", line, formatVersion)
			}
			continue
		}
		b64.WriteString(line)
	}

	if !found {
		return nil, ErrNoBlob
	}
	raw, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		return nil, fmt.Errorf("corrupt report block (base64 decode failed — was the whole block copied?): %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("corrupt report block (not valid gzip): %w", err)
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("corrupt report block (decompress/CRC failed — block was truncated or altered): %w", err)
	}
	return out, nil
}

// stripQuote removes a leading email/chat reply-quote prefix (">", "> ", ">>")
// so a blob pasted from a quoted reply still decodes.
func stripQuote(s string) string {
	s = strings.TrimLeft(s, " \t")
	for strings.HasPrefix(s, ">") {
		s = strings.TrimLeft(strings.TrimPrefix(s, ">"), " \t")
	}
	return s
}
