#!/usr/bin/env bash
# Build dsd .deb and .rpm packages for linux amd64 + arm64 using nfpm.
#
#   scripts/build-packages.sh <version>     # e.g. 0.6.1 (no leading "v")
#
# Cross-compiles the CGO-free linux binaries (if not already in dist/), then
# runs nfpm once per (arch × format). Output lands in dist/:
#   dsd_<version>_amd64.deb  dsd-<version>.x86_64.rpm
#   dsd_<version>_arm64.deb  dsd-<version>.aarch64.rpm
#
# Deps: go, nfpm (https://nfpm.goreleaser.com — `brew install nfpm`).
set -euo pipefail

VERSION="${1:?usage: build-packages.sh <version>  (e.g. 0.6.1)}"
VERSION="${VERSION#v}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p dist

command -v nfpm >/dev/null 2>&1 || { echo "ERROR: nfpm not found (brew install nfpm)" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

MODULE="github.com/keyorixhq/dashdiag"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo none)"
# Reproducible: stamp build time from the version tag's commit, not "now".
BUILT="$(git log -1 --format=%cd --date=format:%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
FLAGS="-X ${MODULE}/internal/version.Version=v${VERSION} -X ${MODULE}/internal/version.Commit=${COMMIT} -X ${MODULE}/internal/version.Built=${BUILT} -s -w"

for ARCH in amd64 arm64; do
  BIN="dist/dsd-linux-${ARCH}"
  if [ ! -x "$BIN" ]; then
    echo "→ building ${BIN}"
    GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -ldflags "$FLAGS" -trimpath -o "$BIN" ./cmd/dsd
  fi
  # Render a concrete config for this arch (nfpm's env expansion does not cover
  # the contents.src glob, so substitute deterministically with sed).
  RENDERED="${TMP}/nfpm-${ARCH}.yaml"
  sed -e "s/\${VERSION}/${VERSION}/g" -e "s/\${ARCH}/${ARCH}/g" \
    packaging/nfpm/nfpm.yaml > "$RENDERED"
  for FORMAT in deb rpm; do
    echo "→ packaging ${ARCH} ${FORMAT}"
    nfpm package --config "$RENDERED" --packager "$FORMAT" --target dist/
  done
done

echo "✅ Packages in dist/:"
ls -1 dist/*.deb dist/*.rpm 2>/dev/null
