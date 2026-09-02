#!/usr/bin/env bash
# scripts/fuzz-discover.sh — single source of truth for "every FuzzXxx target
# in this module." Used by scripts/fuzz-continuous.sh, the Makefile
# (test-fuzz / test-fuzz-linux / test-fuzz-all via scripts/run-fuzz-targets.sh),
# and fuzz_coverage_test.go. A second, independent implementation of this
# discovery is a second thing that can drift — which is exactly how
# `make test-fuzz`'s old hardcoded list silently missed 18 of 44 real FuzzXxx
# functions for months (docs/CONTINUOUS_FUZZING.md), then a further 5 after a
# second hardcoded list (test-fuzz-linux) was added alongside it instead of
# replacing the pattern.
#
# Usage: scripts/fuzz-discover.sh [all|portable|linux]
#   all       every FuzzXxx this host's toolchain can compile+run (respects
#             the CURRENT GOOS's build tags — on macOS that's the portable
#             subset only, since //go:build linux files don't compile here)
#   portable  every FuzzXxx NOT gated behind `//go:build linux` — the subset
#             that also runs on macOS, i.e. what local `make test-fuzz` runs
#   linux     every FuzzXxx that IS gated behind `//go:build linux`
#
# portable/linux categorize by which source file defines the target (its
# name always ends in _linux_test.go for the linux-only files, the project's
# existing naming convention for platform-gated files — see CLAUDE.md). This
# categorization only decides which LOCAL make target / CI job a target is
# grouped under; it never gates whether a target is discovered at all — `all`
# always reflects exactly what `go test -list` finds on this host, full stop.
#
# Output: one `FuncName:package/import/path` pair per line.
#
# Guards must fail loudly (see CONTRIBUTING.md): every command whose failure
# would change the answer here is captured into a variable first, never piped
# through `< <(...)` — a process substitution's exit status is invisible to
# `set -e`, so a failing `go list`/`go test -list` would otherwise just look
# like "fewer packages/targets" instead of an error. This is not theoretical:
# a syntax error in ANY _test.go file in a package — not even a Fuzz-related
# one — used to make that whole package's targets vanish from `all` mode
# silently (exit 0, no stderr). Reproduced live during the adversarial review
# that found this: breaking internal/collectors/cpu_test.go's syntax dropped
# `all` mode's output from 24 to 10 targets with zero indication anything was
# wrong.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-all}"
case "$mode" in
  all|portable|linux) ;;
  *) echo "usage: $0 [all|portable|linux]" >&2; exit 1 ;;
esac

# Bare assignment (not inside if/while) IS covered by set -e: if `go list`
# fails, the script aborts here with its real stderr, rather than silently
# iterating over whatever partial package list happened to print before it
# died.
pkgs=$(go list ./...)

emitted=0
while read -r pkg; do
  [[ -z "$pkg" ]] && continue

  # `if ! var=$(cmd); then` captures both output AND exit status without
  # tripping set -e early — the assignment is exempt from -e specifically
  # because it's the condition of an if. This is what distinguishes "this
  # package genuinely has no fuzz targets" (go test -list succeeds, finds
  # nothing matching ^Fuzz — fine, common) from "this package would not
  # compile" (go test -list itself fails — fatal): piping straight through
  # `grep ... || true` made those two cases produce identical output before.
  if ! list_output=$(go test -list '^Fuzz' "$pkg" 2>&1); then
    echo "fuzz-discover.sh: ${pkg} failed to compile — go test -list exited non-zero:" >&2
    echo "$list_output" >&2
    exit 1
  fi
  names=$(grep -E '^Fuzz' <<<"$list_output" || true)

  for name in $names; do
    if [[ "$mode" == "all" ]]; then
      echo "${name}:${pkg}"
      emitted=$((emitted + 1))
      continue
    fi
    dir="${pkg#github.com/keyorixhq/dashdiag/}"
    [[ "$dir" == "$pkg" ]] && dir="."
    file=$(grep -lE "^func ${name}\(" "${dir}"/*_test.go 2>/dev/null | head -1)
    if [[ "$file" == *_linux_test.go ]]; then
      category="linux"
    else
      category="portable"
    fi
    if [[ "$category" == "$mode" ]]; then
      echo "${name}:${pkg}"
      emitted=$((emitted + 1))
    fi
  done
done <<<"$pkgs"

# Discovery returning zero targets should never be a silent success — with
# one legitimate, permanent exception: `linux` mode has nothing to show on a
# non-Linux host (//go:build linux files don't compile there, by design; see
# `make test-fuzz-linux` on macOS). Every other zero-result combination means
# the discovery mechanism itself broke, not that it genuinely found nothing.
if (( emitted == 0 )) && ! { [[ "$mode" == "linux" ]] && [[ "$(go env GOOS)" != "linux" ]]; }; then
  echo "fuzz-discover.sh: found zero targets for mode '${mode}' on GOOS=$(go env GOOS) — discovery may be broken, not just empty" >&2
  exit 1
fi
