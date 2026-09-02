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
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-all}"
case "$mode" in
  all|portable|linux) ;;
  *) echo "usage: $0 [all|portable|linux]" >&2; exit 1 ;;
esac

while read -r pkg; do
  names=$(go test -list '^Fuzz' "$pkg" 2>/dev/null | grep -E '^Fuzz' || true)
  for name in $names; do
    if [[ "$mode" == "all" ]]; then
      echo "${name}:${pkg}"
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
    [[ "$category" == "$mode" ]] && echo "${name}:${pkg}"
  done
done < <(go list ./... 2>/dev/null)
