# DashDiag Architecture

This document explains the *why* behind architectural decisions.

## The Core Constraint

Single static binary, zero runtime dependencies. `curl` it to a production server,
run it immediately. No Go runtime, no Python, no shared libraries. CGO disabled.

## The Pipeline

```
cmd → runner → collectors → models ← analysis ← render ← output
                    ↑                              ↑
                platform                        platform
```

Data flows **left to right, never backwards**. Enforced by import rules in
`.cursorrules`. The Go compiler enforces it via import cycles.

## Why Collectors Never Set Status

Thresholds change:
- A 4-core server with load 3.5 is WARN; a 64-core server is healthy
- Cloud VMs have different IO limits than bare metal
- Users configure custom thresholds in `~/.dsd.yaml`

If thresholds live in collectors, every threshold change touches every collector.
In the analysis layer, one change in `heuristics.go` covers all cases.

## Concurrency Model

One goroutine per collector. Each bounded by `collector.Timeout()`.
Results stream through a channel to the renderer.

`dsd health` feels instantaneous because memory/CPU results (fast, ~50ms)
start rendering while the IO collector (slow, 1s sample) is still running.
This streaming is the primary technique that makes a 5-second check feel fast.

## Platform Abstraction

```
internal/platform/
├── linux.go       (build tag: //go:build linux)
├── macos.go       (build tag: //go:build darwin)
├── container.go   (all platforms — cgroup v1/v2 detection)
└── cloud.go       (all platforms — DMI files + metadata fallback)
```

Cloud detection uses DMI file reads (< 1ms, no network) with the
`169.254.169.254` metadata endpoint as a 150ms-timeout last resort.
On non-cloud servers, detection adds < 5ms total.

## The TUI Boundary

`bubbletea` is used in exactly TWO places:
- `dsd init` profile selection wizard (SingleSelect)
- `dsd hook install` multi-select

Nowhere else. DashDiag is a snapshot tool that exits. A persistent TUI
dashboard would make it a different product (`btop`, `lazydocker` already exist).

## Output to stderr vs stdout

All progress, tips, milestones, and NPS prompts go to **stderr**.
Health check results go to **stdout**.

```bash
dsd health --json | jq '.checks[] | select(.status == "CRIT")'
```

Progress bar appears on terminal (stderr) without contaminating the JSON (stdout).

## Exit Codes (public contract — never change)

```
0 = all checks OK or INFO
1 = at least one WARN
2 = at least one CRIT (or unexpected error)
```

## JSON Schema Stability

`schema/dsd-output.json` is a public contract. Rules:
- Never remove a field from a published schema version
- Never change the type of an existing field
- Adding new optional fields is backward compatible
- New required fields require a major version bump

*For running commands, read `Makefile`.*
