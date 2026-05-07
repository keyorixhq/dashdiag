## Summary

<!-- What does this PR do? Why? One paragraph max. -->

## Type of change

- [ ] Bug fix
- [ ] New feature / collector
- [ ] Refactor (no behaviour change)
- [ ] Documentation
- [ ] CI / tooling

## Checklist

- [ ] `make check` passes (format + vet + lint)
- [ ] `make test` passes with race detector
- [ ] New collectors have: unit tests + fixtures + golden file
- [ ] New thresholds are in `analysis/heuristics.go` ONLY
- [ ] `dsd health --json | python3 -m json.tool` produces valid JSON
- [ ] `--plain` output contains no ANSI escape codes
- [ ] No new dependencies without justification below

## New dependency justification (if any)

<!-- What does it do? Why can't stdlib do it? License? Maintenance status? -->

## Screenshots / output (if applicable)

```
paste dsd output here
```
