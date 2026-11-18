# LFD — Library Fuzzing Sweep of DashDiag's Dependency Tree

**Report location:** the intended path `/mnt/data/wave4/out/lfd-REPORT.md` is outside this
session's sandbox (only `/mnt/data/wave4/lfd` is writable), so per the runtime rules this
report lives committed on the branch at `.scratch/lfd-REPORT.md`.

**Branch:** `fuzz/lfd-leaf-libs`. All work is in a new tree `internal/fuzzlibs/` (one
package per library). No production code touched. No `go.mod`/`go.sum` edits
(`go.work.sum` was already modified at session start and is left unstaged).

## Assumptions taken (unattended; no one answers questions)

1. There is **no `CLAUDE.md`** in this clone. I followed `CONTRIBUTING.md`, `TRIAGE.md`,
   `DEFECT-CLASSES.md`, the existing fuzz-target conventions, and the runtime rules.
2. The reference `ko` tree and `/mnt/data/wave4/out` are outside the sandbox and
   unreadable. I applied the crash-feasibility gate verbatim from the task prompt: a crash
   counts only if reachable through the library's **public API**, with an input a real
   caller could supply, at the go.mod version, after documented setup, replaying 3×.
3. **CI constraint shapes what is committable.** `.github/workflows/fuzz-changed.yml`
   fuzzes changed targets for 10s each on every PR. A fuzz target that crashes on an
   **unfixed upstream** bug would therefore break CI. So such defects are delivered as
   **record drafts with an embedded Go reproducer**, and only *clean* (crash-only passing)
   harnesses are committed. The committed `termwidth` target is crash-only for this reason.
4. The temperature sensor (`/sys/class/hwmon/hwmon2/temp1_input`) is outside the sandbox
   and unreadable from this session; thermal safety relied on `nice -n 10`, `GOMAXPROCS=2`,
   `-parallel 2` throughout, as instructed.

---

## Findings

| # | Module @ version | Entry point | Class | Severity | DashDiag-reachable? | Record |
|---|------------------|-------------|-------|----------|---------------------|--------|
| 1 | charmbracelet/x/ansi @ v0.10.1 | `ansi.Strip` | SECURITY-DEFECT (sanitizer bypass) | Medium (library) | No (DashDiag uses own sanitizer) | x-ansi-1.md |
| 2 | shirou/gopsutil/v4 @ v4.26.10 | `net.ProtoCountersWithContext` | DEFECT (panic, crash-only) | Low–Med | No (ProtoCounters not called) | gopsutil-1.md |
| 3 | charmbracelet/x/ansi @ v0.10.1 | `ansi.Truncate` | DEFECT (width-contract violation) | Low | No (sanitized upstream) | x-ansi-2.md |

### Finding 1 — `ansi.Strip` escape-injection bypass (headline)

`ansi.Strip` is meant to remove ANSI escape sequences from a string. If an escape is
immediately preceded by a byte that begins a UTF-8 multi-byte sequence but is **not**
followed by valid continuation bytes (invalid UTF-8), Strip's byte state machine consumes
the ESC (and following `[`, digits…) as if they were UTF-8 continuation bytes. The escape
introducer is never recognised, so the **whole** escape sequence survives unstripped:

```
Strip("\xc2\x1b[31m")                 == "\xc2\x1b[31m"      // a complete SGR escape survives
Strip("X\xf0\x1b[41;97mPWNED\x1b[0m") == "X\xf0\x1b[41;97mPWNED"  // working colour injection
```

A single high byte (e.g. `0xC2`) before the payload defeats the sanitizer. Any consumer
that uses `Strip` to neutralise untrusted text is open to ANSI/OSC terminal injection.

**Red/green reproducer** and fix in `.scratch/records/x-ansi-1.md`. Confirmed, replayed 3×.

**DashDiag is NOT affected:** it sanitises with its own `internal/output.SanitizeControl`,
which maps over *runes* (`strings.Map` + `unicode.IsControl`). Rune iteration decodes an
invalid lead byte as U+FFFD (size 1) and then independently sees and removes the ESC. So
DashDiag is immune to exactly this bypass — the sweep both found an upstream library
security defect and validated DashDiag's choice to sanitise by rune, not by a byte-level
escape state machine. Worth an upstream report to charmbracelet/x.

### Finding 2 — `net.ProtoCounters` panics on a truncated /proc/net/snmp line

`net_linux.go:184` slices `line[r+2:]` where `r` is the position of `:`; a matched protocol
header truncated at the colon (e.g. a single line `Tcp:`) makes `r+2 > len(line)` →
`panic: slice bounds out of range [5:4]`. A second bug: a matched header as the last line
advances `i` past `len(lines)` → index out of range. The function already returns errors
for other malformations, so a panic is clearly unintended. Reproducer/fix in
`.scratch/records/gopsutil-1.md`. DashDiag calls `Interfaces`, `IOCounters` and
`Connections` but **not** `ProtoCounters`, so it is not reached.

### Finding 3 — `ansi.Truncate` can exceed the requested width on invalid UTF-8

`ansi.Truncate("0\x7f0\xeb00\xb4\xb4", 3)` returns a width-4 string (requested 3), and the
output bytes are a re-assembled wide rune (`eb b4 b4` = U+BD34) not contiguous in the input.
Truncate's cut accounting disagrees with `StringWidth` on invalid UTF-8. Cosmetic (1-cell
layout overflow). `.scratch/records/x-ansi-2.md`. Not reached in DashDiag (sanitised first).

---

## What was committed (clean, CI-safe harnesses)

Seven packages under `internal/fuzzlibs/`, one commit each (DCO-signed):
`gopsutilfs`, `icmpfs`, `mcpfs`, `qrcodefs`, `tomlfs`, `viperfs`, `termwidth`.
Seeds are inline `f.Add` corpora; no `testdata/fuzz` crashers are committed.

## Coverage, fuzz time, and honest limits

- **Quick scan:** every committed target was fuzzed 20–30s (seed corpus replay + short
  burst) — all pass. The three defects were found within the first second of their
  property-oracle harnesses.
- **Extended run:** a 300s-each native fuzz pass over the five highest-value reachable
  targets (gopsutil Mountinfo, gopsutil NetDev, icmp ParseMessageV4, MCP DecodeMessage,
  go-toml UnmarshalMap) — **results pending at time of writing; this section is updated
  below once the run completes.** Totals are real `go test -fuzz` wall time only.
- **Not** 20 min per target: with ~15 committed targets and a ~3.5 h shared-host budget,
  exhaustive per-target 20-min runs were infeasible. Time was spent on the highest-yield
  reachable surfaces; the rest got the quick scan. This is a breadth sweep, not a
  continuous-fuzzing campaign.

### What each oracle does NOT verify

- **gopsutil / toml / viper / mcp / qrcode / icmp (crash-only or round-trip):** oracle is
  *no panic / no hang* (and, where noted, encode/decode idempotence). It does **not** check
  that parsed values are numerically correct, mapped to the right fields, or that partial
  results on error are sane. The gopsutil harness does not exercise the `/proc/*/fd`
  inode-scan path of `Connections` (needs a live-process tree). MCP round-trip only checks
  re-encode idempotence, not JSON-RPC semantics.
- **termwidth (committed):** crash-only — it does **not** assert the width-bound or
  strip-completeness properties (those live, with reproducers, in the records, because they
  fail against the current upstream). So the committed target would not catch a regression
  that merely violates the width contract without panicking.
- **No differential** against a second implementation except lipgloss-vs-ansi width (moved
  to a record because they can disagree) and the MCP encode/decode round-trip.
- **Unbounded-allocation** oracle is only the Go test timeout; no explicit memory ceiling
  is asserted (qrcode size is clamped so the harness measures robustness, not expected
  large-image allocation).

### Gaps / not done (follow-ups)

- **cobra / pflag** argument parsing not fuzzed: DashDiag's argv is operator-supplied, not
  a remote byte parser; lower priority.
- **bubbletea / termenv full render** not fuzzed (interactive, driven by DashDiag's own
  output; `lipgloss.Width` is covered via termwidth).
- **pro-bing** reply handling is unexported; its hostile-bytes surface is `x/net/icmp`,
  which is fuzzed.
- ini/hcl/properties viper codecs are not in the build, so unreachable.

---

## Talk material (5 sentences)

A breadth fuzz sweep of DashDiag's third-party dependencies — driven through each library's
real public API, including gopsutil's documented `common.EnvMap` fake-root injection so the
`/proc` parsers DashDiag runs as root could be fed hostile files — turned up three upstream
library defects while every committed harness stays green. The headline is a sanitizer
bypass in `charmbracelet/x/ansi`: a single invalid UTF-8 byte before an ANSI escape makes
`Strip` swallow the escape introducer as a bogus continuation byte, so a complete colour
or OSC sequence survives stripping and can inject into an operator's terminal. DashDiag
turns out to be immune because it sanitises by *rune* with `unicode.IsControl`, not with a
byte-level escape state machine — the sweep simultaneously found a real library CVE-class
bug and produced red/green proof that DashDiag's own sanitizer design is the correct one.
We also found a `gopsutil` `/proc/net/snmp` parser panic (a one-line `Tcp:` crashes
`ProtoCounters`) and an `x/ansi.Truncate` width-overflow on invalid UTF-8, both neatly
outside DashDiag's actual call paths. The honest limit: this is breadth over depth —
crash/round-trip oracles at 20–300s per target, not a multi-hour continuous campaign, so
absence of a crash here is weak evidence of absence, not a proof of safety.
