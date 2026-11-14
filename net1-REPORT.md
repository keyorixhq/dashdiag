# NET1 — fuzzing pro-bing / go-sdk (MCP) / cobra+viper / go-qrcode as DashDiag calls them

Branch `fuzz/net-cli-mcp` (from origin/main 096ef46a). Status: IN PROGRESS (early report).

## Readings taken (no one to ask)

- The repo has no CLAUDE.md, INVARIANTS.md/INVARIANTS.d, changelog.d or
  scripts/fuzzing/targets.d; fuzz targets are discovered automatically by
  `scripts/fuzz-discover.sh` (guarded by `fuzz_coverage_test.go`). So: no
  targets.d conf, no changelog fragment, no INVARIANTS.d entry — those
  mechanisms do not exist here. Report lives at `net1-REPORT.md` like the
  sibling `d1-REPORT.md` convention.
- "Promote" = commit as a discovered `FuzzXxx` target with seeds.

## Committed so far

| Commit | What |
|---|---|
| (1) | `FuzzMCPJSONRPCToolArgs`, `FuzzSafeBundlePathContainment`, NET1-F1 reproducer |

## Findings so far

- NET1-F1 (CANDIDATE): directory-symlink escape of `safeBundlePath` — see below.
