# Contributing to DashDiag

## Quick Start

```bash
git clone https://github.com/keyorixhq/dashdiag
cd dashdiag
go mod download
make tools
make hooks
make all
```

## Project Layout

```
dashdiag/
├── cmd/                  # command files — wiring only, 80 lines max each
├── internal/
│   ├── collectors/       # one file per collector — pure data readers
│   ├── models/           # dumb structs — no logic, no methods
│   ├── analysis/         # heuristics.go — ONLY place thresholds live
│   ├── render/           # one file per output format
│   ├── output/           # tty.go, progress.go — terminal utilities
│   ├── platform/         # linux.go, macos.go, container.go, cloud.go
│   ├── baseline/         # --diff and --since-deploy infrastructure
│   ├── tips/             # tips.go, milestones.go — retention features
│   ├── tui/              # select.go — bubbletea (wizards only)
│   ├── init/             # detector.go, firstrun.go — onboarding wizard
│   ├── config/           # config.go — ~/.dsd.yaml loading
│   └── version/          # version string injected at build time
├── testdata/
│   ├── fixtures/         # fake /proc and /sys for unit tests
│   ├── golden/           # expected renderer output (committed)
│   └── fuzz/             # fuzz corpus (committed)
├── schema/               # dsd-output.json — public JSON contract
├── scripts/              # smoke-test.sh, hooks/pre-commit, hooks/pre-push
└── SPEC.md               # product bible — read before writing any code
```

**Read `SPEC.md` before writing code.** It contains architecture decisions,
data models, and design constraints that govern everything in this project.

## Architecture in One Paragraph

Data flows one direction:
```
cmd → runner → collectors → models ← analysis ← render ← output
```
Collectors read system state and return raw data. Analysis applies thresholds
and produces insights. Renderers format output. Commands are wiring only.
**Nothing flows backwards.** A collector never imports analysis. A model never
has methods. An analysis function never reads from the filesystem.

## Development Workflow

### For a bug fix
```bash
git checkout -b fix/describe-the-bug
# make your change
make check        # must pass
make test         # must pass
git commit -m "fix: describe the fix"
```

### For a new collector
Every collector needs four things:
```
internal/collectors/<name>.go          # the collector
internal/collectors/<name>_test.go     # table-driven unit tests
testdata/fixtures/<name>/linux.txt     # fake /proc or /sys content
testdata/golden/<name>_healthy.txt     # expected output (generated)
```

Run `make golden-update` after writing your renderer to generate the golden file.

## Commit Message Format

```
feat: add --since-deploy flag
fix: network collector panics on no IPv4 address
test: add fuzz corpus for /proc/diskstats parser
docs: update CONTRIBUTING with golden file instructions
chore: update dependencies
```

## Pull Request Checklist

- [ ] `make check` passes (format + vet + lint)
- [ ] `make test` passes with race detector
- [ ] New collectors have: unit tests + fixtures + golden file
- [ ] New thresholds are in `analysis/heuristics.go` ONLY (never in collectors)
- [ ] `dsd health --json | python3 -m json.tool` still produces valid JSON
- [ ] `--plain` output has no ANSI escape codes
- [ ] No new dependencies without discussion in PR description

## Testing

```bash
make test                  # unit tests — run constantly during development
make cover                 # unit tests + HTML coverage report
make test-integration      # real syscalls — run before pushing
make golden-update         # update golden files when output changes intentionally
go test -fuzz=FuzzParseLoadAvg ./internal/collectors/ -fuzztime=60s
```

## Adding a Dependency

New dependencies require justification. In your PR, answer:
1. What does it do?
2. Why can't stdlib do it?
3. What is the license? (must be MIT, Apache 2.0, or BSD)
4. What is the maintenance status?

## Security

Found a vulnerability? Email security@dashdiag.sh — **not** a public issue.
