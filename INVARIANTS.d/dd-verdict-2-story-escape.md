# INVARIANTS — DD-VERDICT-2 Part C: story-narration terminal-escape safety

Targets: `internal/render` · `FuzzRenderStoryNoTerminalInjection`
(`internal/render/ddverdict2_story_escape_fuzz_test.go`) — the story-funnel companion
to DL1's `FuzzRenderFunnelNoTerminalInjection`, which deliberately excluded the story
path (its public entry `RenderStory` calls `baseline.LoadHistory`, disk I/O).

Scope: the two in-memory, deterministic story builders — `renderStorySinglePoint` and
`renderStoryFromHistory` — driven end-to-end with a hostile-byte corpus (raw CSI, OSC
52/8, raw C1 introducers, window-title rewrite, bidi override/isolate, line-forge,
C0, invalid UTF-8, DEL) planted into every host-derived string field at once, across
the active-insight, floored "unverified checks", current-issues, and Processes
zombie-offender branches.

- **S1 no raw terminal control (LOAD-BEARING).** `assertNoTerminalInjection` (shared
  with the DL1 target): rendered output is valid UTF-8, contains no raw ESC (0x1B, the
  CSI/OSC gate), no C1 control byte, no unicode control rune except the `\n` DashDiag
  emits, and no bidi-formatting rune (Trojan-Source / CVE-2021-42574 class). This is
  the same host-string invariant every DashDiag funnel upholds, now asserted on the
  story builders that `story.go` routes through `output.SanitizeControl` (hostname
  :32/:73, ins.Check/Message :45/:57, c.Name/c.Value/c.Status, zombie offender).

Positive control: both builders must actually surface the planted host string (a plain
token appears in the single-point head line and in the from-history events), so S1 can
never pass vacuously against a builder that emitted nothing host-derived.

Red/green (throwaway, never committed): removing ONE `output.SanitizeControl` call in
`renderStorySinglePoint` (on `ins.Message`) made S1 go RED on the seed corpus (raw ESC
reached the output). GREEN with the shipped sanitiser in place.

CheckResult.Status: planted too. `storyEvents` sanitises the stored status
(`output.SanitizeControl(c.Status)`) so `e.to` is terminal-safe at both print sites,
like `c.Name` and `c.Value`.

Does NOT verify: the on-disk `baseline.LoadHistory` path (inputs are in-memory), any
styled lipgloss/TUI story variant, bounded work/allocation (DL1/TU1 carry the render
resource oracle), and any narration format these two builders do not emit.
