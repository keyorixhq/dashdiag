#!/usr/bin/env bash
# CI fuzz smoke — discovers every FuzzXxx target and runs each for FUZZTIME
# (default 30s) using the existing corpus. Intended to run on every PR so a
# broken fuzz target fails the gate rather than silently disappearing from the
# continuous rig's rotation (scripts/fuzz-continuous.sh handles the long runs).
#
# This is a targeted sanity check, not a corpus-building session. No corpus
# files are committed; a crash reproducer lands in testdata/fuzz/<Func>/ via
# Go's normal fuzz mechanism and is uploaded by the CI job's artifact step.
set -euo pipefail

FUZZTIME="${FUZZTIME:-30s}"
failed=0

# Discover targets without process substitution: store package list in a variable
# so the while-read loop runs in the current shell (a pipe would fork a subshell
# and 'exit 1' from the inner go test call wouldn't propagate to the caller).
all_pkgs=$(go list ./...)

while IFS= read -r pkg; do
  # 'go test -list' exits 0 and prints nothing when there are no FuzzXxx functions.
  fuzz_fns=$(go test -list '^Fuzz' "$pkg" 2>/dev/null | grep '^Fuzz' || true)
  if [[ -z "$fuzz_fns" ]]; then
    continue
  fi
  while IFS= read -r fn; do
    echo "--- $fn ($pkg) for $FUZZTIME ---"
    if ! go test -run=NONE "-fuzz=^${fn}$" "-fuzztime=${FUZZTIME}" "$pkg"; then
      echo "FAIL: $fn in $pkg"
      failed=$((failed + 1))
    fi
  done <<< "$fuzz_fns"
done <<< "$all_pkgs"

if [[ "$failed" -gt 0 ]]; then
  echo "fuzz smoke: $failed target(s) failed"
  exit 1
fi
echo "fuzz smoke: all targets passed"
