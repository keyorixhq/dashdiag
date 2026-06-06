#!/usr/bin/env bash
# Build dsd AppImages for linux amd64 + arm64.
#
#   scripts/build-appimage.sh <version>     # e.g. 0.6.1 (no leading "v")
#
# Why AppImage: the Steam Deck (and every SteamOS device) ships an immutable,
# read-only rootfs — anything dropped in /usr/local/bin is wiped on the next OS
# update, and the bundled package manager is disabled. An AppImage is a single
# self-contained file the user downloads and runs from $HOME; it survives every
# update. This is the install story behind the SteamOS viral-channel strategy
# (DashDiag_Project_Guide.md §31). dsd is a static CGO-free binary, so the
# AppImage is a thin wrapper — no bundled libraries.
#
# Cross-builds both arches from a single host: appimagetool runs on the host
# arch but embeds the *target* runtime selected by the ARCH env var, so an
# x86_64 CI runner can emit the aarch64 AppImage too.
#
# Output lands in dist/:
#   dsd-<version>-x86_64.AppImage
#   dsd-<version>-aarch64.AppImage
#
# Deps: go, plus appimagetool (auto-downloaded to dist/ if not on PATH).
set -euo pipefail

VERSION="${1:?usage: build-appimage.sh <version>  (e.g. 0.6.1)}"
VERSION="${VERSION#v}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p dist

MODULE="github.com/keyorixhq/dashdiag"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo none)"
# Reproducible: stamp build time from HEAD's commit date, not "now" (matches
# scripts/build-packages.sh).
BUILT="$(git log -1 --format=%cd --date=format:%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
FLAGS="-X ${MODULE}/internal/version.Version=v${VERSION} -X ${MODULE}/internal/version.Commit=${COMMIT} -X ${MODULE}/internal/version.Built=${BUILT} -s -w"

# --- locate appimagetool (extracted, so it needs no FUSE) ---------------------
HOST_ARCH="$(uname -m)"   # x86_64 | aarch64
TOOL_DIR="${ROOT}/dist/.appimagetool"
TOOL="${TOOL_DIR}/squashfs-root/AppRun"
if ! command -v appimagetool >/dev/null 2>&1 && [ ! -x "$TOOL" ]; then
  echo "→ fetching appimagetool (${HOST_ARCH})"
  mkdir -p "$TOOL_DIR"
  URL="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-${HOST_ARCH}.AppImage"
  curl -fsSL "$URL" -o "${TOOL_DIR}/appimagetool.AppImage"
  chmod +x "${TOOL_DIR}/appimagetool.AppImage"
  # Extract instead of running directly — CI runners usually lack FUSE.
  ( cd "$TOOL_DIR" && ./appimagetool.AppImage --appimage-extract >/dev/null )
fi
APPIMAGETOOL="$(command -v appimagetool || echo "$TOOL")"

# --- build one AppImage per arch ---------------------------------------------
# GOARCH -> AppImage arch name (appimagetool's ARCH + output suffix).
declare -A ARCHNAME=( [amd64]=x86_64 [arm64]=aarch64 )

for GOARCH in amd64 arm64; do
  AIARCH="${ARCHNAME[$GOARCH]}"
  BIN="dist/dsd-linux-${GOARCH}"
  if [ ! -x "$BIN" ]; then
    echo "→ building ${BIN}"
    GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build -ldflags "$FLAGS" -trimpath -o "$BIN" ./cmd/dsd
  fi

  APPDIR="$(mktemp -d)"
  trap 'rm -rf "$APPDIR"' EXIT
  install -Dm0755 "$BIN"                          "${APPDIR}/usr/bin/dsd"
  install -Dm0755 packaging/appimage/AppRun       "${APPDIR}/AppRun"
  install -Dm0644 packaging/appimage/dsd.desktop  "${APPDIR}/dsd.desktop"
  install -Dm0644 packaging/appimage/dsd.png      "${APPDIR}/dsd.png"
  # appimagetool also looks for the icon under the hicolor theme path.
  install -Dm0644 packaging/appimage/dsd.png \
    "${APPDIR}/usr/share/icons/hicolor/256x256/apps/dsd.png"

  OUT="dist/dsd-${VERSION}-${AIARCH}.AppImage"
  echo "→ packaging ${AIARCH} -> ${OUT}"
  # ARCH selects the embedded runtime; --no-appstream keeps the build offline.
  ARCH="$AIARCH" "$APPIMAGETOOL" --no-appstream "$APPDIR" "$OUT"

  rm -rf "$APPDIR"
  trap - EXIT
done

echo "✅ AppImages in dist/:"
ls -1 dist/*.AppImage 2>/dev/null
