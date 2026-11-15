# charmbracelet/x/ansi `Strip` lets ANSI escape sequences bypass when preceded by an invalid UTF-8 lead byte

- **Module:** github.com/charmbracelet/x/ansi
- **Version:** v0.10.1 (as in go.mod; latest in module cache)
- **Class:** SECURITY-DEFECT (sanitizer bypass → terminal escape injection). Not a panic.
- **Severity:** Medium. `ansi.Strip` is advertised/used as a way to remove ANSI escape
  sequences from strings before display. A one-byte prefix defeats it, so any consumer
  that relies on `Strip` to neutralise untrusted text is subject to ANSI/OSC escape
  injection (cursor moves, screen/clobber, title rewrite, on some emulators OSC 52
  clipboard writes).
- **Public entry point:** `ansi.Strip(string) string`

## Trigger

If an ANSI escape sequence is immediately preceded by a byte that begins a UTF-8
multi-byte sequence but is **not** followed by valid continuation bytes (i.e. invalid
UTF-8), `Strip`'s byte state machine consumes the ESC (and, for longer lead bytes, the
following `[`, intermediate, etc.) as if they were UTF-8 continuation bytes. The ESC is
therefore never recognised as an escape introducer, and the **entire** escape sequence
passes through unstripped.

Minimal: a single `\xc2` (a 2-byte UTF-8 lead expecting 1 continuation) before a complete
SGR escape:

```
Strip("\xc2\x1b[31m")            == "\xc2\x1b[31m"     // ESC + SGR survive
Strip("\xf0\x1b[31mZ")          == "\xf0\x1b[31mZ"     // 4-byte lead, same
Strip("X\xf0\x1b[41;97mPWNED\x1b[0m") == "X\xf0\x1b[41;97mPWNED"  // working injection survives
```

Contrast (works correctly without the prefix):

```
Strip("\x1b")        == ""      // lone ESC removed
Strip("\x1b[31mX\x1b[0m") == "X" // escapes removed
```

Confirmed deterministically, replayed 3×.

## Minimal reproducer (Go test, red/green)

```go
package repro

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestStripBypass(t *testing.T) {
	// A complete SGR color escape, preceded by one invalid UTF-8 lead byte.
	in := "\xc2\x1b[31mred\x1b[0m"
	out := ansi.Strip(in)
	if strings.ContainsRune(out, 0x1b) {
		t.Fatalf("Strip left an escape introducer: %q -> %q", in, out)
	}
}
```

Fails on v0.10.1 (ESC survives); would pass once Strip decodes invalid UTF-8 one byte
at a time (as the correct behaviour).

## Expected vs actual

- **Expected:** `Strip` removes every ANSI escape sequence regardless of surrounding
  (even invalid-UTF-8) bytes; no ESC (0x1b) remains.
- **Actual:** an invalid UTF-8 lead byte swallows the following ESC, so the escape — and
  any attacker-chosen payload after it — survives.

## Suggested fix

`Strip`'s parser must not let an invalid UTF-8 lead byte consume subsequent C0 control
bytes (especially ESC 0x1b). When a continuation byte is not a valid UTF-8 continuation
(`b&0xC0 != 0x80`), the lead byte should be emitted as a single (replacement) byte and
parsing must resume at the next byte so ESC is re-evaluated as an escape introducer. I.e.
decode the invalid lead byte as exactly one byte (like `utf8.DecodeRuneInString`'s
RuneError, size 1), not as the start of a fixed-length multi-byte run.

## DashDiag reachability

**NOT reachable as a DashDiag vulnerability.** DashDiag does **not** use `ansi.Strip` to
sanitise untrusted text; it rolls its own `internal/output.SanitizeControl`, which maps
over *runes* (`strings.Map` + `unicode.IsControl`). Ranging over runes decodes an invalid
UTF-8 lead byte as U+FFFD of size 1 and then independently sees the ESC, which is a
control rune and is removed. So DashDiag's sanitizer is immune to exactly this bypass:

```
SanitizeControl("\xc2\x1b[31mred\x1b[0m") == "�[31mred[0m"   // ESC removed
```

This is a library-level security defect worth reporting upstream; no DashDiag change is
needed. It also validates DashDiag's decision to sanitise by rune rather than via a
byte-level escape state machine.
