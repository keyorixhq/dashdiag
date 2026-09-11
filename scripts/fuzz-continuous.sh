#!/usr/bin/env bash
# Continuous fuzzing loop for dashdiag's Go fuzz targets — the always-on
# complement to the per-release `make test-fuzz`/`test-fuzz-linux` ritual
# (see docs/CONTINUOUS_FUZZING.md for the full rationale and rig setup).
#
# Deliberately does NOT hardcode a target list: `make test-fuzz` hardcoded one
# and silently missed 18 of 44 real FuzzXxx functions for months before anyone
# noticed. This script re-discovers every fuzz target across the whole module
# on every rotation via scripts/fuzz-discover.sh (`go test -list` under the
# hood — the SAME mechanism the Makefile and CI use), so it can't go stale
# the same way, and can't quietly drift from what CI runs either.
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
# How many times to retry a failed fetch, and the base backoff between tries.
FETCH_RETRIES="${FETCH_RETRIES:-5}"
FETCH_BACKOFF="${FETCH_BACKOFF:-10}"

cd "$REPO_DIR"

log() { echo "[$(date -u +%FT%TZ)] $*"; }

# alert() is for events a human should actually see (crash found, rotation
# summary) — routine per-target lines just use log(). Keeps NOTIFY_URL from
# turning into a firehose if it's wired to a push service.
alert() {
  log "$*"
  if [[ -n "$NOTIFY_URL" ]]; then
    curl -fsS -m 10 -d "$*" "$NOTIFY_URL" >/dev/null 2>&1 || true
  fi
}

# Per-run logs under $FUZZ_LOG_DIR (default ~/fuzz-logs), gzipped and never
# overwritten, and a GitHub tracking-issue copy of every failing run's log —
# see the header of that file for why. Sourced once, at startup.
# shellcheck source=scripts/fuzz-runlog.sh
source "$REPO_DIR/scripts/fuzz-runlog.sh"
# sync_repo's `git clean -fd` would delete logs kept inside the checkout.
case "$FUZZ_LOG_DIR/" in
  "$(pwd -P)/"*)
    echo "FUZZ_LOG_DIR=$FUZZ_LOG_DIR is inside the checkout $(pwd -P) — sync_repo would delete it; point it elsewhere" >&2
    exit 1
    ;;
esac

sync_repo() {
  # A failed fetch must NEVER take the service down. Under the old code a single
  # `git fetch` failure (a DNS blip, a brief network drop — routine on the vCD
  # tenant) exited the script under `set -e`; systemd's Restart then relaunched
  # it, and with a per-target fetch a flaky network turned into a restart loop
  # that fuzzed almost nothing for days. Retry with backoff, and if the fetch
  # still fails, reset to whatever origin/main we already have and fuzz that
  # (stale main is far better than no fuzzing) rather than exiting.
  local i
  for ((i = 1; i <= FETCH_RETRIES; i++)); do
    if git fetch "$REMOTE" main -q 2>/dev/null; then
      break
    fi
    if [[ "$i" -eq FETCH_RETRIES ]]; then
      log "fetch of $REMOTE/main still failing after $FETCH_RETRIES attempts — fuzzing the existing checkout instead of exiting"
      break
    fi
    log "fetch of $REMOTE/main failed (attempt $i/$FETCH_RETRIES) — retrying in $((FETCH_BACKOFF * i))s"
    sleep "$((FETCH_BACKOFF * i))"
  done
  git checkout main -q
  git reset --hard "$REMOTE/main" -q
  git clean -fd -q
}

# Every FuzzXxx function across the module, paired with its package. Cheap
# (a few seconds per rotation, not per target) since it only lists, never
# runs. Delegates to scripts/fuzz-discover.sh — the same discovery the
# Makefile and CI use — rather than a second inline implementation.
discover_targets() {
  "$REPO_DIR/scripts/fuzz-discover.sh" all
}

# A crash reproducer lands in testdata/fuzz/<Func>/ automatically — that's Go's
# own fuzz engine behaviour, not something this script arranges. Non-crashing
# "new interesting" corpus (the majority of what a fuzz run finds) stays in the
# local build cache ($GOCACHE/fuzz) and is never written into the source tree.
# So any diff here is, by construction, an actual failing input worth a human
# looking at — there's no separate "just growing the corpus" case to handle.
#
# Optional args: func pkg logfile — when supplied, the PR body and any comment
# include the crash summary and reproduce command for that specific target.
# Called without args as a safety-net sweep at end of rotation (no-op if clean).
publish_crashers() {
  local func="${1:-}" pkg="${2:-}" logfile="${3:-}"

  # Same reason this isn't `git status --porcelain ... | grep -q .`: grep -q
  # exits on its first match, which can SIGPIPE git status while it's still
  # writing (multiple changed files) — under this script's `set -o pipefail`,
  # that would make the whole check report "nothing to publish" even when a
  # real crash reproducer exists. Capture first, then test on the variable.
  status_output=$(git status --porcelain -- '*/testdata/fuzz/*')
  if [[ -z "$status_output" ]]; then
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
  git commit -q --signoff -m "test(fuzz): crash reproducer(s) from continuous fuzzing ($(date -u +%F))"
  git push -f -u "$REMOTE" "$CORPUS_BRANCH" -q

  # Build PR title/body and comment text with crash context when available.
  if [[ -n "$func" && -n "$pkg" && -n "$logfile" ]]; then
    reproduce_cmd="go test -run=^${func}\$ ${pkg}"
    # zgrep: the run log has already been gzipped by runlog_finish.
    summary="$(zgrep -m8 -E 'FAIL|panic:|--- FAIL|Fatalf|\.go:[0-9]+' "$logfile" | head -c 1500 || true)"
    pr_title="fuzz(crash): $func — crash reproducer"
    pr_body="## Fuzz crash: \`$func\`

**Package:** \`$pkg\`

**Reproduce:**
\`\`\`
$reproduce_cmd
\`\`\`

**Failure:**
\`\`\`
${summary:-see log on the fuzz box}
\`\`\`

Each file under \`*/testdata/fuzz/\` in this PR is a crashing input found by the continuous fuzz rig. Fix the bug, add coverage, then merge this PR to lock the regression test in permanently."
    comment_body="**New crash ($(date -u +%FT%TZ)):** \`$func\` in \`$pkg\`
\`\`\`
${summary:-see log on the fuzz box}
\`\`\`
Reproduce: \`$reproduce_cmd\`"
  else
    pr_title="test(fuzz): crash reproducer(s) from continuous fuzzing"
    pr_body="Auto-opened by the continuous-fuzzing rig (scripts/fuzz-continuous.sh). Each file under \`*/testdata/fuzz/\` here is an input that made a FuzzXxx target fail — reproduce locally with \`go test -run=<FuzzName> ./<package>/\`. Nothing here auto-merges; review like any other PR."
    comment_body="Additional crash reproducer(s) added ($(date -u +%FT%TZ))."
  fi

  if ! gh pr view "$CORPUS_BRANCH" >/dev/null 2>&1; then
    gh pr create --head "$CORPUS_BRANCH" --base main \
      --title "$pr_title" \
      --body "$pr_body" \
      >/dev/null || true
  else
    pr_number="$(gh pr view "$CORPUS_BRANCH" --json number --jq '.number' 2>/dev/null || true)"
    if [[ -n "$pr_number" ]]; then
      gh pr comment "$pr_number" --body "$comment_body" >/dev/null || true
    fi
  fi

  git checkout main -q
}

# Flush failing-run logs a previous process queued but could not post.
runlog_post_pending

rotation=0
while true; do
  rotation=$((rotation + 1))
  sync_repo
  # Capture before looping, and check the exit status explicitly — this rig
  # is the one consumer of fuzz-discover.sh that branch protection does not
  # cover (it force-syncs straight to origin/main), so a discover_targets
  # failure here can't rely on a PR check catching it. `mapfile -t targets <
  # <(discover_targets)` would hide that failure from `set -e` entirely (a
  # process substitution's exit status is invisible to it) and silently
  # mapfile whatever partial output printed before fuzz-discover.sh died —
  # exactly the same "fewer targets, no error" shape this rig exists to avoid.
  raw_targets=$(discover_targets) || { alert "discover_targets failed on $(hostname) — fuzz-discover.sh could not enumerate targets, rotation $rotation aborted"; exit 1; }
  mapfile -t targets <<<"$raw_targets"
  alert "rotation $rotation: fuzzing ${#targets[@]} targets, ${FUZZTIME} each"
  for entry in "${targets[@]}"; do
    # Re-sync before EVERY target, not just once per rotation. A rotation
    # covers 44+ targets at $FUZZTIME each — hours, sometimes most of a day —
    # and this codebase merges frequently enough that a target near the end
    # of the list was otherwise fuzzing code that could be many hours stale.
    sync_repo
    name="${entry%%:*}"
    pkg="${entry#*:}"
    # The target list was snapshotted at the top of this rotation; syncing
    # every iteration now means a target can be renamed/removed by the time
    # we reach it. Confirm it still exists before fuzzing it — otherwise
    # `go test -fuzz` fails to match anything and that failure would get
    # mistaken for a real crash.
    # Capture first, then grep — NOT `go test -list ... | grep -qx`. grep -q
    # exits the instant it finds a match, closing its end of the pipe while
    # `go test` is often still writing its trailing "ok <pkg> <time>" summary
    # line; the resulting SIGPIPE makes `go test` exit non-zero, and with
    # `set -o pipefail` (active in this script) that failure propagates to
    # the whole pipeline even though grep DID find the match. Confirmed live:
    # every target read as "no longer exists" on a real run, despite existing,
    # because this script has pipefail on and an ad-hoc manual reproduction
    # attempt (without pipefail) couldn't see the bug at all.
    list_output=$(go test -list "^${name}\$" "$pkg" 2>/dev/null || true)
    if ! grep -qx "$name" <<<"$list_output"; then
      log "$name no longer exists in $pkg (renamed/removed since rotation start) — skipping"
      continue
    fi
    runlog_start "$name" "$pkg" "$FUZZTIME"
    status=0
    go test -run=NONE -fuzz="^${name}\$" -fuzztime="$FUZZTIME" "$pkg" >>"$RUNLOG" 2>&1 || status=$?
    # Seal and queue the log BEFORE anything that talks to the network:
    # publish_crashers pushes under `set -e`, so a failed push exits the
    # script, and the log must already be safe (and queued for GitHub) by then.
    runlog_finish "$status"
    if [[ "$status" -ne 0 ]]; then
      # A non-zero exit is only a CRASH if Go actually wrote a reproducer into
      # testdata/fuzz/. Most non-zero exits are NOT crashes: a `context deadline
      # exceeded` at the end of -fuzztime (a Go fuzzing harness flake), an
      # out-of-memory kill, or a build/network failure — 34 of the 37 CRASH
      # alerts this rig raised in 2026-07/08 were the end-of-fuzztime flake, and
      # the loud alert on every one of them trained everyone to ignore it. Only
      # a real reproducer gets the alert + PR; everything else is a quiet logged
      # failure (runlog has already queued its log to the tracking issue).
      if [[ -n "$(git status --porcelain -- '*/testdata/fuzz/*')" ]]; then
        alert "CRASH: $name ($pkg) on $(hostname), exit $status — reproducer written, log at $RUNLOG_FINAL. Reproduce with: go test -run=$name $pkg"
        publish_crashers "$name" "$pkg" "$RUNLOG_FINAL" # commit the reproducer immediately, don't wait for end of rotation
      else
        log "$name exited $status with no reproducer (timeout/OOM/build/network) — logged to the tracking issue, not a crash"
      fi
    fi
    runlog_post_pending
  done
  publish_crashers # safety net — no-op if the loop above already published
  alert "rotation $rotation complete"
done
