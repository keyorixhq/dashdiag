// SPDX-License-Identifier: BSD-3-Clause

// Package qrcodefs fuzzes github.com/skip2/go-qrcode encoding, which DashDiag
// calls on share URLs (internal/output/qr.go: qrcode.New(url, qrcode.Medium)).
//
// Oracle: no panic, bounded work (per-input test timeout). The PNG size
// parameter is clamped to a sane range so the harness measures encoder
// robustness, not expected large-image allocation.
package qrcodefs

import (
	"testing"

	"github.com/skip2/go-qrcode"
)

func FuzzNew(f *testing.F) {
	f.Add("https://example.com/s/abc123")
	f.Add("")
	f.Add("\x00\x01\x02\xff\xfe")
	f.Fuzz(func(t *testing.T, content string) {
		// Over-capacity content legitimately returns an error; that's fine.
		qr, err := qrcode.New(content, qrcode.Medium)
		if err != nil || qr == nil {
			return
		}
		// Rendering to a bounded PNG must not panic.
		_, _ = qr.PNG(256)
	})
}

// FuzzEncode exercises qrcode.Encode with a clamped size.
func FuzzEncode(f *testing.F) {
	f.Add("hello", 256)
	f.Add("", 0)
	f.Add("x", -1)
	f.Fuzz(func(t *testing.T, content string, size int) {
		// Clamp size: negative/zero is a valid input to exercise, but a huge
		// positive size is expected to allocate a large image (not a defect).
		if size > 1024 {
			size = 1024
		}
		if size < -8 {
			size = -8
		}
		_, _ = qrcode.Encode(content, qrcode.Medium, size)
	})
}
