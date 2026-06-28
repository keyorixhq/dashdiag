#!/usr/bin/env bash
# check-replay-fidelity.sh — guard against the "cross-environment replay-fidelity"
# bug class: a collector that reads live ENVIRONMENT state at `dsd replay` time
# (container-context, adjtimex/clock-sync, kernel, arch) instead of from the
# bundle, so replay reports the replaying machine's findings under the captured
# host's name rather than the captured host's findings. The first instance shipped
# was the clock collector flipping a captured "NTP not synchronized" CRIT into a
# green "host: synced" OK when replayed inside a container (#586).
#
# WHY THE EXISTING DOUBLE-REPLAY JOB CAN'T CATCH THIS: the replay-hermetic job
# captures and replays in the SAME environment and asserts two replays agree. When
# capture-env == replay-env, a live env-read returns the same value both times, so
# the divergence is invisible. You only see it when the replay environment DIFFERS
# from the captured host's.
#
# HOW THIS GUARD WORKS: it replays a committed bundle captured on a DISTINCTIVE
# host (one whose verdicts differ from any CI runner — see
# fixtures/replay-fidelity/README.md) inside a CONTAINER (a deliberately divergent
# environment: container-context flips, different kernel/arch, captured host's
# tools absent). Under faithful replay the output is a pure function of the bundle,
# so every check's status MUST match the checked-in golden regardless of where it
# runs. A drift means a collector read live state — fail loud.
#
# Requires: docker, jq, go (only if $DSD is not prebuilt). Runs in CI (ubuntu
# runner) and locally on any host with docker (builds a static linux binary for
# the docker default arch, so it runs natively under OrbStack on Apple Silicon).
set -euo pipefail

FIXTURE_DIR="${FIXTURE_DIR:-fixtures/replay-fidelity}"
IMAGE="${IMAGE:-debian:13-slim}"

command -v docker >/dev/null || { echo "FAIL: docker is required (the divergent replay environment)" >&2; exit 1; }
command -v jq >/dev/null || { echo "FAIL: jq is required" >&2; exit 1; }

# Build a STATIC linux binary (CGO_ENABLED=0 → runs in any image) for the arch the
# local docker daemon serves by default, so the container can exec it natively.
# Build into the repo root (not $TMPDIR): docker bind-mounts must come from a
# path the daemon shares with containers, and on macOS/OrbStack $TMPDIR
# (/var/folders/…) is NOT shared while the working tree is. Cleaned up on exit.
DSD="${DSD:-}"
if [ -z "$DSD" ]; then
  DSD="$(mktemp "$PWD/.dsd-fidelity.XXXXXX")"
  trap 'rm -f "$DSD"' EXIT
  ARCH="${GOARCH:-$(go env GOARCH)}"
  echo "building static dsd (linux/$ARCH) -> $DSD"
  CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$DSD" ./cmd/dsd
fi

STATUS_JQ='[.checks[] | {(.name): .status}] | add'
FAIL=0
FOUND=0

for bundle in "$FIXTURE_DIR"/*.tar.gz; do
  [ -e "$bundle" ] || { echo "FAIL: no fixtures in $FIXTURE_DIR" >&2; exit 1; }
  golden="${bundle%.tar.gz}.golden.json"
  name="$(basename "$bundle" .tar.gz)"
  # docker bind-mount sources must be absolute paths (a relative one errors 125).
  bundle="$(cd "$(dirname "$bundle")" && pwd)/$(basename "$bundle")"
  FOUND=$((FOUND + 1))
  if [ ! -f "$golden" ]; then
    echo "FAIL: $name has no golden ($golden)" >&2; FAIL=1; continue
  fi

  # Recording-gap check: replay must not announce an input it never captured.
  if docker run --rm -v "$DSD":/dsd:ro -v "$bundle":/b.tar.gz:ro "$IMAGE" \
       /dsd replay /b.tar.gz 2>&1 >/dev/null | grep -qi "not present in replay"; then
    echo "::error::$name: replay hit a recording gap — a collector read an uncaptured input" >&2
    FAIL=1; continue
  fi

  # Replay in the container, reduce to a check->status map, compare to golden.
  actual="$(docker run --rm -v "$DSD":/dsd:ro -v "$bundle":/b.tar.gz:ro "$IMAGE" \
             /dsd replay --json /b.tar.gz 2>/dev/null | jq -S "$STATUS_JQ")"
  want="$(jq -S . "$golden")"

  if [ "$actual" == "$want" ]; then
    echo "OK: $name — all $(echo "$want" | jq 'length') check verdicts match the golden under container replay"
  else
    echo "::error::$name: replayed verdicts differ from the golden — a collector reads live environment state under replay (cross-env fidelity regression, see #586)" >&2
    echo "  --- diff (want vs replayed) ---" >&2
    diff <(echo "$want") <(echo "$actual") >&2 || true
    FAIL=1
  fi
done

[ "$FOUND" -gt 0 ] || { echo "FAIL: no *.tar.gz fixtures found in $FIXTURE_DIR" >&2; exit 1; }
if [ "$FAIL" -ne 0 ]; then
  echo >&2
  echo "Replay must reproduce the CAPTURED host, not the replaying machine. Route the" >&2
  echo "offending live read through internal/source (Source.Cached/Stat/…). See" >&2
  echo "fixtures/replay-fidelity/README.md and ADR-0003." >&2
  exit 1
fi
echo "✅ cross-env replay fidelity: $FOUND fixture(s) reproduce their golden verdicts under container replay"
