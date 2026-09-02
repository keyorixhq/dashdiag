#!/usr/bin/env bash
# scripts/check-release-drift.sh — fails loudly when a pushed tag has no
# corresponding published, signed GitHub release.
#
# Written after v2.0.1-v2.1.0 were briefly (and wrongly) believed to have
# silently failed to publish — a stale read of the releases page, not a real
# incident. The gap this guards against is still real: a tag pushed while a
# required secret is missing, or a runner image change breaks the release
# job, leaves no release and nothing today notices. Compares local tag refs
# (after `git fetch --tags`) against `gh release view` for every tag older
# than the grace window, and also requires checksums.txt.minisig on each
# release — dsd update / install.sh fail closed on an unsigned release, so a
# missing signature is a quieter failure than a missing release entirely.
set -euo pipefail
cd "$(dirname "$0")/.."

TAG_PATTERN="${TAG_PATTERN:-v*}"
GRACE_HOURS="${GRACE_HOURS:-4}"
# Signing (checksums.txt.minisig) was only activated at v1.17.2 (2026-07-06,
# see docs/RELEASE.md) — every tag before that is legitimately unsigned.
# Bounding to recent tags keeps the check meaningful (did the LAST release
# actually ship) instead of red forever over pre-signing history it can't
# fix. 30 days comfortably spans the real v2.x release cadence (max gap
# between v2.x tags so far: 5 days) with margin for a slow month.
LOOKBACK_DAYS="${LOOKBACK_DAYS:-30}"
REPO="${REPO:-keyorixhq/dashdiag}"

now_epoch=$(date -u +%s)
grace_seconds=$((GRACE_HOURS * 3600))
lookback_seconds=$((LOOKBACK_DAYS * 86400))

drift=0
checked=0

# Capture before looping (see CONTRIBUTING.md's "guards must fail loudly"
# rule): a bare assignment IS covered by set -e, so a git for-each-ref
# failure aborts here with its real error, instead of `done < <(...)` — whose
# exit status set -e can't see — silently handing the loop whatever tags
# printed before it died. A mid-stream failure would otherwise just look
# like "fewer tags to check," not an error, in a script whose entire job is
# noticing exactly that shape of problem.
tags_output=$(git for-each-ref "refs/tags/${TAG_PATTERN}" --format='%(refname:short) %(creatordate:unix)')

while IFS=' ' read -r tag created_epoch; do
  [[ -z "$tag" ]] && continue

  age=$((now_epoch - created_epoch))
  if (( age > lookback_seconds )); then
    continue
  fi
  checked=$((checked + 1))

  if (( age < grace_seconds )); then
    echo "SKIP  $tag (tagged $(( age / 60 ))m ago, within ${GRACE_HOURS}h grace window)"
    continue
  fi

  if ! release_json=$(gh release view "$tag" --repo "$REPO" --json isDraft,isPrerelease,assets 2>/dev/null); then
    echo "DRIFT $tag: tagged $(( age / 3600 ))h ago, no GitHub release found"
    drift=1
    continue
  fi

  is_draft=$(jq -r '.isDraft' <<<"$release_json")
  is_prerelease=$(jq -r '.isPrerelease' <<<"$release_json")
  has_sig=$(jq -r '[.assets[].name] | any(. == "checksums.txt.minisig")' <<<"$release_json")

  if [[ "$is_draft" == "true" ]]; then
    echo "DRIFT $tag: release exists but is still a draft"
    drift=1
  elif [[ "$is_prerelease" == "true" ]]; then
    echo "DRIFT $tag: release exists but is marked prerelease"
    drift=1
  elif [[ "$has_sig" != "true" ]]; then
    echo "DRIFT $tag: release is published but missing checksums.txt.minisig"
    drift=1
  else
    echo "OK    $tag"
  fi
done <<<"$tags_output"

if (( checked == 0 )); then
  echo "No tags matched pattern '${TAG_PATTERN}' within the last ${LOOKBACK_DAYS} days — nothing to check." >&2
  exit 1
fi

echo
if (( drift == 1 )); then
  echo "Release drift detected — see DRIFT lines above." >&2
  exit 1
fi

echo "No release drift: every tag past the ${GRACE_HOURS}h grace window has a published, signed release."
