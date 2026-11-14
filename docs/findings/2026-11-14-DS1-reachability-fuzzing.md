# DS1: reachability-first fuzzing for DashDiag (2026-11-14)

Branch `fuzz/reachability-ds1` from `096ef46a` (origin/main). Status: IN PROGRESS.

## Readings taken (nobody to ask)

- The task names "the report path given in your task"; none was given, so the
  report lives here, next to the other `docs/findings/` reports.
- There is no CLAUDE.md, INVARIANTS.md, `scripts/fuzzing/targets.d/` or
  `changelog.d/` in this repo. Fuzz targets are discovered automatically by
  `scripts/fuzz-discover.sh`, guarded by `fuzz_coverage_test.go`; no conf file
  is needed. Nothing ships, so no CHANGELOG entry.
- `internal/yamlsafe` does not exist on main. It is the proposed hardening on
  branch `chore/yaml-go-yaml-in` (`cb9cc021`, PR #1179). To fuzz "the
  duplicate-key hardening path" I copied its body verbatim into a test-only
  file (`internal/analysis/yamlsafe_copy_test.go`) running on the same library
  (`go.yaml.in/yaml/v3` v3.0.5, already in this module's graph; its
  `decode.go` is byte-identical to the v3.0.6 the branch pins).

(sections below are filled in as results arrive)
