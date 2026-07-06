#!/usr/bin/env bash
# Continuous fuzzing loop for dashdiag's Go fuzz targets — the always-on
# complement to the per-release `make test-fuzz`/`test-fuzz-linux` ritual
# (see docs/CONTINUOUS_FUZZING.md for the full rationale and rig setup).
#
# Deliberately does NOT hardcode a target list: `make test-fuzz` hardcoded one
# and silently missed 18 of 44 real FuzzXxx functions for months before anyone
# noticed. This script re-discovers every fuzz target across the whole module
# on every rotation via `go test -list`, so it can't go stale the same way.
#
# Intended host: a dedicated, disposable Linux box (LXC/VM), not a dev
# machine — every rotation force-syncs to origin/main and wipes untracked
# files. Never develop or leave uncommitted work in this checkout.
set -euo pipefail

REPO_DIR="${REPO_DIR:-$HOME/proj/dashdiag}"
FUZZTIME="${FUZZTIME:-15m}"
NOTIFY_URL="${FUZZ_NOTIFY_URL:-}"
CORPUS_BRANCH="${CORPUS_BRANCH:-fuzz/corpus-updates}"
REMOTE="${REMOTE:-origin}"

cd "$REPO_DIR"

log() { echo "[$(date -u +%FT%TZ)] $*"; }

# alert() is for events a human should actually see (crash found, rotation
# summary) — routine per-target lines just use log(). Keeps NOTIFY_URL from
# turning into a firehose if it's wired to a push service.
alert() {
  log "$*"
  if [ -n "$NOTIFY_URL" ]; then
    curl -fsS -m 10 -d "$*" "$NOTIFY_URL" >/dev/null 2>&1 || true
  fi
}

sync_repo() {
  git fetch "$REMOTE" main -q
  git checkout main -q
  git reset --hard "$REMOTE/main" -q
  git clean -fd -q
}

# Every FuzzXxx function across the module, paired with its package. Cheap
# (a few seconds per rotation, not per target) since it only lists, never runs.
discover_targets() {
  local pkg names name
  while read -r pkg; do
    names=$(go test -list '^Fuzz' "$pkg" 2>/dev/null | grep -E '^Fuzz' || true)
    for name in $names; do
      echo "${name}:${pkg}"
    done
  done < <(go list ./... 2>/dev/null)
}

# A crash reproducer lands in testdata/fuzz/<Func>/ automatically — that's Go's
# own fuzz engine behaviour, not something this script arranges. Non-crashing
# "new interesting" corpus (the majority of what a fuzz run finds) stays in the
# local build cache ($GOCACHE/fuzz) and is never written into the source tree.
# So any diff here is, by construction, an actual failing input worth a human
# looking at — there's no separate "just growing the corpus" case to handle.
publish_crashers() {
  if ! git status --porcelain -- '*/testdata/fuzz/*' | grep -q .; then
    return 0
  fi
  alert "new fuzz crash reproducer(s) found — opening/updating PR on $CORPUS_BRANCH"
  # Re-sync to the LATEST origin/main first. sync_repo only runs once per full
  # rotation (up to ~11h), so the checkout a crash is found against can be
  # badly stale by the time this runs. Basing the corpus branch on a stale
  # point is not just cosmetic: GitHub rejects a push from a token with no
  # `workflow` scope if the pushed tree's .github/workflows/* content differs
  # from what's already known, even when the actual new commit never touches
  # a workflow file — confirmed live (2026-07-06) when a real crash PR failed
  # to push for exactly this reason. `git reset --hard` only touches TRACKED
  # files, so the untracked crash reproducer survives this refresh untouched.
  git fetch "$REMOTE" main -q
  git checkout main -q
  git reset --hard "$REMOTE/main" -q
  git checkout -B "$CORPUS_BRANCH" -q
  git add -- '*/testdata/fuzz/*'
  git commit -q -m "test(fuzz): crash reproducer(s) from continuous fuzzing ($(date -u +%F))"
  git push -f -u "$REMOTE" "$CORPUS_BRANCH" -q
  if ! gh pr view "$CORPUS_BRANCH" >/dev/null 2>&1; then
    gh pr create --head "$CORPUS_BRANCH" --base main \
      --title "test(fuzz): crash reproducer(s) from continuous fuzzing" \
      --body "Auto-opened by the continuous-fuzzing rig (scripts/fuzz-continuous.sh). Each file under */testdata/fuzz/ here is an input that made a FuzzXxx target fail — reproduce locally with \`go test -run=<FuzzName> ./<package>/\`. Nothing here auto-merges; review like any other PR." \
      >/dev/null || true
  fi
  git checkout main -q
}

rotation=0
while true; do
  rotation=$((rotation + 1))
  sync_repo
  mapfile -t targets < <(discover_targets)
  alert "rotation $rotation: fuzzing ${#targets[@]} targets, ${FUZZTIME} each"
  for entry in "${targets[@]}"; do
    name="${entry%%:*}"
    pkg="${entry#*:}"
    logfile="/tmp/fuzz-$(echo "$name" | tr -cd 'A-Za-z0-9_').log"
    if ! go test -run=NONE -fuzz="^${name}\$" -fuzztime="$FUZZTIME" "$pkg" > "$logfile" 2>&1; then
      alert "CRASH: $name ($pkg) on $(hostname) — log at $logfile. Reproduce with: go test -run=$name $pkg"
      publish_crashers # commit the reproducer immediately, don't wait for end of rotation
    fi
  done
  publish_crashers # safety net — no-op if the loop above already published
  alert "rotation $rotation complete"
done
