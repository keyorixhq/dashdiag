// SPDX-License-Identifier: BSD-3-Clause

// Package termwidth fuzzes the terminal width/truncation/strip functions of
// charmbracelet/x/ansi (and lipgloss.Width, which wraps it). DashDiag renders
// hostile strings through lipgloss: process names, hostnames, log lines and
// command output read from /proc and from external tools can contain escape
// sequences, wide/combining runes and invalid UTF-8.
//
// These committed targets are CRASH-ONLY (oracle: no panic, no hang). The
// stronger width/strip *property* oracles found two real, still-unfixed defects
// in x/ansi v0.10.1 on invalid-UTF-8 input (see .scratch/records/x-ansi-1.md,
// x-ansi-2.md). Those property assertions are intentionally NOT committed here,
// because the per-PR CI (fuzz-changed.yml) fuzzes changed targets and would
// crash on the upstream bug; the reproducers live in the records instead.
package termwidth

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var widthSeeds = []string{
	"hello",
	"\x1b[31mred\x1b[0m",
	"ｗｉｄｅ",             // fullwidth
	"áb",            // combining accent
	"\xff\xfe\x00",        // invalid UTF-8 + NUL
	"\xc2\x1b[31mx\x1b[0m", // invalid lead byte before an escape
	"\x1b]8;;http://x\x07link\x1b]8;;\x07", // OSC hyperlink
}

func FuzzStringWidth(f *testing.F) {
	for _, s := range widthSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = ansi.StringWidth(s)
		_ = ansi.StringWidthWc(s)
		_ = ansi.Strip(s)
		if !strings.Contains(s, "\n") {
			_ = lipgloss.Width(s)
		}
	})
}

func FuzzTruncate(f *testing.F) {
	f.Add("\x1b[31mhello world\x1b[0m", 5)
	f.Add("ｗｉｄｅ文字", 3)
	f.Add("ábc\xeb\xb4", 2)
	f.Fuzz(func(t *testing.T, s string, n int) {
		if n < 0 || n > 1<<16 {
			return
		}
		_ = ansi.Truncate(s, n, "")
		_ = ansi.TruncateLeft(s, n, "")
		_ = ansi.Cut(s, 0, n)
	})
}

func FuzzWrap(f *testing.F) {
	f.Add("the quick brown fox jumps", 8)
	f.Add("\x1b[31mcolored and long text here\x1b[0m", 6)
	f.Add("ｗｉｄｅ文字が続く行", 5)
	f.Fuzz(func(t *testing.T, s string, limit int) {
		if limit <= 0 || limit > 1<<16 {
			return
		}
		_ = ansi.Hardwrap(s, limit, false)
		_ = ansi.Wrap(s, limit, "")
	})
}
