# INVARIANTS — MC1 third-party target: charmbracelet/x/ansi

Target: `internal/thirdpartyfuzz/ansienc` · `FuzzAnsiWidthTruncateWrap`.

Scope: the width / truncate / wrap layer DashDiag reaches through lipgloss when it
measures and lays out host-derived terminal text (`render.StyleXxx.Render(host)`).
`ansi.StringWidth`/`ansi.Strip` are reachable today; `ansi.Truncate`/`Wrap`/
`Hardwrap` are reached only when a style sets a width (none do yet) and are held
as library-level (upstream-style) invariants.

## Asserted (held across millions of execs)

- **W3 no ESC from host.** If the input has no ESC (0x1B), no output of
  Truncate/Hardwrap/Wrap does: the layer must never SYNTHESISE a terminal escape
  from plain host text. **(Load-bearing security invariant.)**
- **W4 no new introducer.** Truncate/Hardwrap/Wrap never increase the ESC count
  (`count(out) <= count(in)`): no escape introducer is synthesised or duplicated
  when text is split/rejoined. **(Load-bearing security invariant.)** Strip itself
  must leave no ESC on valid UTF-8.
- **W1 width bound (Truncate only).** `StringWidth(Truncate(s,w,"")) <= w` for
  valid UTF-8 — Truncate drops content to fit.
- **W2 idempotence.** `Truncate(Truncate(s,w,""),w,"") == Truncate(s,w,"")` (valid
  UTF-8) and `Strip(Strip(s)) == Strip(s)` (any bytes).
- **Resource.** Bounded alloc (factor 512) / wall time / no goroutine growth.

## NOT asserted — characterised as findings (fuzzer-disproven, none reachable)

- **F2** Hardwrap per-line width bound and idempotence: Hardwrap refuses to SPLIT
  a grapheme cluster, so a cluster wider than the limit (limit=1 + width-2 char;
  U+0601 U+0601 '0' prepend cluster of width 3 at limit=2) is emitted over-limit
  and re-wrap is not a fixed point. EXPECTED-DIFFERENCE.
- **F3** `Strip` leaves a raw ESC when preceded by an invalid UTF-8 lead byte
  (`Strip("\xe8\x1b") == "\xe8\x1b"`). HARDENING/upstream.
- **F4** `StringWidth(Strip(s)) != StringWidth(s)` when an ESC sits between
  clustering chars (`StringWidth("ꥲ\x1bꥲ")==4` vs `"ꥲꥲ"==2`): the ESC is a
  grapheme boundary. EXPECTED-DIFFERENCE.

None of F2–F4 is reachable from DashDiag: lipgloss sets no width on host text, and
`output.SanitizeControl` replaces invalid UTF-8 / strips controls before any
lipgloss/ansi path. Reported upstream-style, not asserted, never weakened to match.

Red/green: no-op truncate → W1; ESC injector → W3; ESC duplicator → W4;
non-idempotent transform → W2 (all fired; scratch removed).
