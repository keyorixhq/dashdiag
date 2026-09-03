#!/usr/bin/env bash
# scripts/check-release-drift.sh — fails loudly when a pushed tag has no
# corresponding published, signed GitHub release.
#
# Written after v2.0.1-v2.1.0 were briefly (and wrongly) believed to have
# silently failed to publish — a stale read of the releases page, not a real
# incident. The gap this guards against is still real: a tag pushed while a
# required secret is missing, or a runner image change breaks the release
# job, leaves no release and nothing today notices.
#
# Two fixed floor anchors, not sliding windows — each marks when a
# capability started existing for this project, not "how far back we still
# care." A sliding window lets drift heal by being ignored long enough (the
# bug this script used to have, see below); a fixed anchor doesn't move, so
# a tag that fails its check stays flagged forever, not just until nobody's
# looking anymore. This is the general shape of any retrospective check over
# a project's full history: capabilities arrive at different times, so each
# assertion needs its own floor. Two anchors is a pattern now — a third
# (SBOM, attestation, whatever's next) slots in the same way instead of
# sprouting another ad-hoc mechanism.
#
#   RELEASE_PROCESS_START — the GitHub Releases process itself didn't exist
#   for the project's first ~2 weeks. v0.2.0-sprint1, v0.3.0-phase1, v0.4.0,
#   v0.4.1, v0.5.0, and v0.5.1 (all created 2026-05-07 to 2026-05-18) were
#   tagged before the release process stabilized and were never published as
#   GitHub Releases — verified against `gh release list`, not assumed: every
#   tag from v0.6.0 onward (2026-05-20 on) has one. Tier 1 doesn't apply
#   below this floor.
#
#   SIGNING_EPOCH — checksums.txt.minisig activation date (2026-07-06, see
#   docs/RELEASE.md). Every tag before that legitimately has no signature.
#   Tier 2 doesn't apply below this floor.
#
# Two tiers, checked separately, so the second tier's floor can't quietly
# widen into the first:
#   1. Release exists, published, not draft, not prerelease — applies to
#      every tag at or after RELEASE_PROCESS_START.
#   2. Release carries checksums.txt.minisig — applies to every tag at or
#      after SIGNING_EPOCH (a subset of tier 1's range).
# A previous version of this script bounded itself with a 30-day sliding
# LOOKBACK_DAYS window instead of a floor. That mechanism was wrong: a tag
# that fails to publish and goes unnoticed for 31 days would have silently
# stopped being reported — the exact failure mode this script exists to
# catch. Fixed floors don't have that problem; they don't move with "now".
set -euo pipefail
cd "$(dirname "$0")/.."

TAG_PATTERN="${TAG_PATTERN:-v*}"
GRACE_HOURS="${GRACE_HOURS:-4}"
REPO="${REPO:-keyorixhq/dashdiag}"
RELEASE_PROCESS_START="v0.6.0"
SIGNING_EPOCH="v1.17.2"
# Optional push notification (e.g. ntfy) on drift — silent no-op when unset.
# Same pattern as scripts/fuzz-continuous.sh's FUZZ_NOTIFY_URL: a red
# scheduled workflow only helps if a human actually sees it, and GitHub's
# scheduled-failure email is easy to miss or filter.
NOTIFY_URL="${DRIFT_NOTIFY_URL:-}"

now_epoch=$(date -u +%s)
grace_seconds=$((GRACE_HOURS * 3600))

drift=0
checked=0

notify() {
  if [[ -n "$NOTIFY_URL" ]]; then
    curl -fsS -m 10 -d "$*" "$NOTIFY_URL" >/dev/null 2>&1 || true
  fi
}

# version_ge A B: true (exit 0) if version A >= B in version order. Uses
# `sort -V` (GNU coreutils version-sort) rather than a hand-rolled
# comparator — with two floor anchors there are two version comparisons to
# get wrong, and "v1.9.0" vs "v1.17.2" sorts backwards under plain lexical
# comparison (the character '9' > '1') even though "v0.5.1" vs "v0.6.0"
# doesn't. Requires GNU sort; this script only runs in CI on ubuntu-24.04
# (see .github/workflows/release-drift.yml), where that's guaranteed.
version_ge() {
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" == "$1" ]]
}

# Capture before looping (see CONTRIBUTING.md's "guards must fail loudly"
# rule): a bare assignment IS covered by set -e, so a git for-each-ref
# failure aborts here with its real error, instead of `done < <(...)` — whose
# exit status set -e can't see — silently handing the loop whatever tags
# printed before it died.
tags_output=$(git for-each-ref "refs/tags/${TAG_PATTERN}" --format='%(refname:short) %(creatordate:unix)')

while IFS=' ' read -r tag created_epoch; do
  [[ -z "$tag" ]] && continue

  age=$((now_epoch - created_epoch))
  if (( age < grace_seconds )); then
    echo "SKIP  $tag (tagged $(( age / 60 ))m ago, within ${GRACE_HOURS}h grace window)"
    continue
  fi

  if ! version_ge "$tag" "$RELEASE_PROCESS_START"; then
    echo "SKIP  $tag (predates the release process, before ${RELEASE_PROCESS_START})"
    continue
  fi

  checked=$((checked + 1))

  # Tier 1 — every tag at/after RELEASE_PROCESS_START needs a published,
  # non-draft, non-prerelease release.
  if ! release_json=$(gh release view "$tag" --repo "$REPO" --json isDraft,isPrerelease,assets 2>/dev/null); then
    echo "DRIFT $tag: tagged $(( age / 3600 ))h ago, no GitHub release found"
    drift=1
    continue
  fi

  is_draft=$(jq -r '.isDraft' <<<"$release_json")
  is_prerelease=$(jq -r '.isPrerelease' <<<"$release_json")

  if [[ "$is_draft" == "true" ]]; then
    echo "DRIFT $tag: release exists but is still a draft"
    drift=1
    continue
  fi
  if [[ "$is_prerelease" == "true" ]]; then
    echo "DRIFT $tag: release exists but is marked prerelease"
    drift=1
    continue
  fi

  # Tier 2 — signature required only from SIGNING_EPOCH onward.
  if version_ge "$tag" "$SIGNING_EPOCH"; then
    has_sig=$(jq -r '[.assets[].name] | any(. == "checksums.txt.minisig")' <<<"$release_json")
    if [[ "$has_sig" != "true" ]]; then
      echo "DRIFT $tag: release is published but missing checksums.txt.minisig"
      drift=1
      continue
    fi
  fi

  echo "OK    $tag"
done <<<"$tags_output"

# Tier 1 has no sliding window, so every tag matching TAG_PATTERN at/after
# RELEASE_PROCESS_START gets checked — this should be unreachable in a repo
# with any release history past that floor. If it happens anyway (empty
# repo, wrong TAG_PATTERN, or RELEASE_PROCESS_START moved past every tag
# that exists), treat it as a failure, not a silently-successful no-op: a
# check that verified nothing is not a check that passed.
if (( checked == 0 )); then
  echo "No tags matched pattern '${TAG_PATTERN}' at or after ${RELEASE_PROCESS_START} — nothing was checked. Treating as failure, not success." >&2
  notify "Release drift check: no tags matched pattern '${TAG_PATTERN}' at or after ${RELEASE_PROCESS_START} — nothing was checked."
  exit 1
fi

echo
if (( drift == 1 )); then
  echo "Release drift detected — see DRIFT lines above." >&2
  notify "Release drift detected in ${REPO} — see the workflow run for DRIFT lines."
  exit 1
fi

echo "No release drift: every tag past the ${GRACE_HOURS}h grace window has a published release from ${RELEASE_PROCESS_START} onward, signed from ${SIGNING_EPOCH} onward."
