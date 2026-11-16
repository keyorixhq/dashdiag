# INVARIANTS — MC1 third-party target: charmbracelet/x/ansi

Target: `internal/thirdpartyfuzz/ansienc` · `FuzzAnsiWidthTruncateWrap`.

Scope: the width / truncate / wrap layer DashDiag reaches through lipgloss when it
measures and lays out host-derived terminal text (`render.StyleXxx.Render(host)`).
`ansi.StringWidth`/`ansi.Strip` are reachable today; `ansi.Truncate`/`Wrap`/
`Hardwrap` are reached only when a style sets a width (none do yet) and are held
as library-level (upstream-style) invariants.

- **W1 width bound.** `StringWidth(Truncate(s,w,"")) <= w`; every `Hardwrap(s,w)`
  line has `StringWidth(line) <= w`. Output is never wider than the limit given.
  (No lower bound is asserted — a wide grapheme straddling the boundary may yield
  fewer cells, which is correct.)
- **W2 idempotence.** `Truncate`/`Hardwrap` at the same limit, and `Strip`, are
  stable under a second application.
- **W3 no ESC from host.** If the input has no ESC (0x1B), no output does: the
  measurement/wrapping layer must not synthesise a terminal escape from plain
  text.
- **W4 no new introducer.** `Truncate`/`Wrap`/`Hardwrap` never increase the ESC
  count. (The stronger "Strip leaves no ESC" is only asserted for `Strip` itself;
  `ansi.Strip` is lenient about dangling introducers, so it is a dead oracle for
  the wrappers.)
- **W5 width stable across Strip.** `StringWidth(Strip(s)) == StringWidth(s)` for
  valid-UTF-8 `s` (escapes are zero-width).
- **Resource.** Bounded alloc (factor 512) / wall time / no goroutine growth.

Red/green: no-op truncate → W1; ESC injector → W3; ESC duplicator → W4;
non-idempotent transform → W2 (all fired; scratch removed).
