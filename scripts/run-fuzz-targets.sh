#!/usr/bin/env bash
# scripts/run-fuzz-targets.sh — thin runner over scripts/fuzz-discover.sh.
# Backs `make test-fuzz` / `test-fuzz-linux` / `test-fuzz-all` and the CI
# fuzz.yml jobs, so there's exactly one place that decides WHAT to fuzz
# (fuzz-discover.sh) and exactly one place that decides HOW to run it (here).
#
# Usage: scripts/run-fuzz-targets.sh <all|portable|linux> <fuzztime> [shard-index shard-count]
#   shard-index/shard-count (both optional, 0-based index): run only every
#   Nth target starting at shard-index, out of shard-count total shards.
#   Used by CI to split a long discovered list across parallel jobs without
#   needing a second, separately-maintained target list per job — see the
#   wall-clock arithmetic in .github/workflows/fuzz.yml.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:?usage: $0 <all|portable|linux> <fuzztime> [shard-index shard-count]}"
fuzztime="${2:?usage: $0 <all|portable|linux> <fuzztime> [shard-index shard-count]}"
shard_index="${3:-0}"
shard_count="${4:-1}"

count=0
index=0
while IFS=: read -r name pkg; do
  [[ -z "$name" ]] && continue
  if (( index % shard_count != shard_index )); then
    index=$((index + 1))
    continue
  fi
  index=$((index + 1))
  count=$((count + 1))
  echo "→ ${name} (${pkg}, ${fuzztime})"
  go test -run=NONE -fuzz="^${name}\$" -fuzztime="$fuzztime" "$pkg"
done < <(scripts/fuzz-discover.sh "$mode")

if (( count == 0 )); then
  echo "no FuzzXxx targets found for mode '${mode}' shard ${shard_index}/${shard_count} — discovery is broken, not just empty" >&2
  exit 1
fi

echo "✅ ${count} fuzz target(s) passed (mode=${mode} shard=${shard_index}/${shard_count})"
