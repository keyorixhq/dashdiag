# charmbracelet/x/ansi `Truncate` can exceed the requested width on invalid UTF-8

- **Module:** github.com/charmbracelet/x/ansi
- **Version:** v0.10.1
- **Class:** DEFECT (contract violation: output display width > requested width). Not a panic.
- **Severity:** Low (cosmetic: a truncated cell can overflow its column by 1 on malformed
  input; can nudge a table/box layout off by one but no safety impact).
- **Public entry point:** `ansi.Truncate(s string, length int, tail string) string`

## Trigger

With invalid UTF-8 in `s`, `Truncate`'s cut-point accounting disagrees with
`ansi.StringWidth`, and it can emit a string wider than `length`. The truncator skips
invalid continuation bytes and then re-pairs a stray lead byte with later bytes into a
*valid wide rune* that was never present as such in the input.

```
ansi.Truncate("0\x7f0\xeb00\xb4\xb4", 3) == "0\x7f0봴"
// input bytes:  30 7f 30 eb 30 30 b4 b4
// output bytes: 30 7f 30 eb b4 b4   (the two 0x30 between eb and b4b4 are dropped;
//                                    eb b4 b4 is U+BD34 "봴", a width-2 rune)
// StringWidth(output) == 4  >  requested length 3
```

Confirmed deterministically, replayed 3×.

## Minimal reproducer (Go test, red/green)

```go
package repro

import (
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestTruncateWidthOverflow(t *testing.T) {
	const n = 3
	out := ansi.Truncate("0\x7f0\xeb00\xb4\xb4", n, "")
	if w := ansi.StringWidth(out); w > n {
		t.Fatalf("Truncate width %d exceeds requested %d (out=%q)", w, n, out)
	}
}
```

## Expected vs actual

- **Expected:** `StringWidth(Truncate(s, n, "")) <= n` for all `s` and `n >= 0` — Truncate
  and StringWidth should agree on cell width, including for invalid UTF-8.
- **Actual:** width 4 for a requested length of 3, and the output bytes are a re-assembled
  rune not contiguous in the input.

## Suggested fix

Make `Truncate`'s width accounting use the same invalid-UTF-8 decoding as `StringWidth`
(decode one byte → RuneError width when the lead byte is invalid, never re-pair across
intervening bytes), so the two functions never disagree.

## DashDiag reachability

DashDiag renders attacker-influenced text (process/comm names, log lines) through lipgloss,
which uses x/ansi for width and truncation. However, DashDiag sanitises with
`SanitizeControl` first, which replaces invalid UTF-8 with U+FFFD, so the exact malformed
input that triggers this never reaches `Truncate` in practice. Impact is at most a 1-cell
layout overflow and only on un-sanitised paths; treat as a library correctness bug.
Reported for completeness; no DashDiag change required.
