## What this PR does

<!-- One sentence -->

## Type of change

- [ ] Bug fix
- [ ] New feature (backward compatible)
- [ ] Breaking change (changes JSON output schema or exit codes)
- [ ] Documentation / tests only

## Checklist

- [ ] `make check` passes (gofmt + vet + lint)
- [ ] `make test` passes with race detector
- [ ] New collectors have unit tests + fixtures + fuzz test
- [ ] New thresholds are in `analysis/heuristics.go` only — not in collectors
- [ ] `dsd health --json | python3 -m json.tool` still produces valid JSON
- [ ] `dsd health --plain` output has no ANSI escape codes

## If JSON output changed

<!-- Is this backward compatible? What fields changed? -->

## If a new dependency was added

<!-- Why can't stdlib do it? What is the license? -->
