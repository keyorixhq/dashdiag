# UPSTREAM DRAFT (NOT SENT) — charmbracelet/x/ansi: Strip leaves a raw ESC after an invalid UTF-8 lead byte

Target project: **github.com/charmbracelet/x/ansi** (v0.10.1). Status: DRAFT,
held locally (unattended run — nothing is sent). Stand-alone reproducer at
`./F3-repro/`.

## Summary

`ansi.Strip` is intended to remove ANSI escape sequences from a string. When an
ESC (0x1B) is immediately preceded by an **invalid UTF-8 lead byte**, Strip does
NOT remove the escape — the raw ESC (and a following CSI sequence) survives in
the output. A consumer that trusts `Strip`'s output to be escape-free can then be
handed a live terminal escape.

## Reproduction (v0.10.1, go1.27.4)

```
ansi.Strip("\xe8\x1b")       == "\xe8\x1b"        // raw ESC survives
ansi.Strip("\xe8\x1b[31m")   == "\xe8\x1b[31m"    // whole CSI SGR survives
// valid-UTF-8 baselines strip correctly:
ansi.Strip("a\x1b[31mb")     == "ab"
ansi.Strip("x\x1by")         == "x"
```

`0xE8` is a UTF-8 lead byte announcing a 3-byte sequence; `0x1B` is not a valid
continuation, so the input is invalid UTF-8. The scanner appears to consume the
ESC as part of the (broken) multibyte decode, so the escape-sequence recogniser
never sees it as an introducer and it passes through verbatim. The `\xe8\x1b[31m`
case is the sharp one: a fully-formed CSI SGR ("set foreground red") survives a
call whose entire job is to strip such sequences.

## Why it matters

`Strip` is a natural "make this safe to print" primitive. Any pipeline that
sanitises untrusted text with `Strip` before writing it to a terminal — logs,
TUIs, diff/report renderers — assumes the result carries no ESC. An attacker who
can place an invalid UTF-8 byte before an escape (trivial in untrusted bytes:
file names, captured command output, network payloads) defeats that assumption
and smuggles a live escape through. It is a robustness / defense-in-depth gap,
not a memory-safety bug.

## Suggested fix (upstream)

Decode the input defensively: on an invalid UTF-8 sequence, advance by exactly
one byte (the Unicode replacement-character convention) rather than letting the
broken lead byte consume the following ESC. Then the ESC is re-examined as a
potential introducer and stripped like any other. Equivalently, scan for ESC at
the BYTE level independently of UTF-8 decoding, since ESC (0x1B) can never be a
UTF-8 continuation byte.

## Downstream (dsd) relationship — NOT reachable in dsd

dsd reaches x/ansi only through lipgloss when measuring/laying out host-derived
terminal text. Every such string is first run through `output.SanitizeControl`,
which replaces invalid UTF-8 and strips controls BEFORE any lipgloss/ansi call —
so ansi never sees the malformed bytes that trigger this. The MC1 ansi target
(`FuzzAnsiWidthTruncateWrap`) therefore reports F3 upstream-style and scopes its
"Strip leaves no ESC" assertion to VALID UTF-8 (where it holds), rather than
weakening the assertion to accept the surviving ESC. This draft is the upstream
half of that finding.

## Reproducer

`./F3-repro/main.go` (stand-alone module, pinned to x/ansi v0.10.1). `go run .`
prints each case and whether an ESC survived.
