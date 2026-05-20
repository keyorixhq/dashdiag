#!/bin/sh
# DashDiag (dsd) installer
# Usage: curl -fsSL https://raw.githubusercontent.com/keyorixhq/dashdiag/main/install.sh | sh
# Or:    curl -fsSL https://raw.githubusercontent.com/keyorixhq/dashdiag/main/install.sh | sh -s -- --prefix /usr/local

set -e

REPO="keyorixhq/dashdiag"
BINARY="dsd"
PREFIX="${1:-/usr/local}"

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { printf "${BOLD}[dsd]${RESET} %s\n" "$*"; }
success() { printf "${GREEN}✅ %s${RESET}\n" "$*"; }
warn()    { printf "${YELLOW}⚠️  %s${RESET}\n" "$*"; }
die()     { printf "${RED}❌ %s${RESET}\n" "$*" >&2; exit 1; }

# ── detect OS / arch ─────────────────────────────────────────────────────────
detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux)  OS_KEY="linux"  ;;
        Darwin) OS_KEY="darwin" ;;
        *)      die "Unsupported OS: $OS" ;;
    esac

    case "$ARCH" in
        x86_64|amd64) ARCH_KEY="amd64" ;;
        aarch64|arm64) ARCH_KEY="arm64" ;;
        *) die "Unsupported architecture: $ARCH" ;;
    esac

    PLATFORM="${OS_KEY}-${ARCH_KEY}"
}

# ── fetch latest tag from GitHub ─────────────────────────────────────────────
fetch_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
    elif command -v wget >/dev/null 2>&1; then
        VERSION="$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
    else
        die "curl or wget is required"
    fi

    [ -n "$VERSION" ] || die "Could not determine latest version from GitHub"
}

# ── download ─────────────────────────────────────────────────────────────────
download() {
    FILENAME="${BINARY}-${PLATFORM}"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${FILENAME}"
    TMPDIR="$(mktemp -d)"
    TMPFILE="${TMPDIR}/${BINARY}"

    info "Downloading dsd ${VERSION} (${PLATFORM})..."

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --progress-bar "$URL" -o "$TMPFILE" || die "Download failed: $URL"
    else
        wget -q --show-progress "$URL" -O "$TMPFILE" || die "Download failed: $URL"
    fi

    chmod +x "$TMPFILE"
    echo "$TMPFILE"
}

# ── verify checksum ──────────────────────────────────────────────────────────
verify_checksum() {
    TMPFILE="$1"
    SUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
    SUMS_FILE="${TMPDIR}/checksums.txt"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$SUMS_URL" -o "$SUMS_FILE" 2>/dev/null || { warn "Could not fetch checksums -- skipping verification"; return; }
    else
        wget -qO "$SUMS_FILE" "$SUMS_URL" 2>/dev/null || { warn "Could not fetch checksums -- skipping verification"; return; }
    fi

    EXPECTED="$(grep "${BINARY}-${PLATFORM}" "$SUMS_FILE" | awk '{print $1}')"
    [ -n "$EXPECTED" ] || { warn "No checksum found for ${BINARY}-${PLATFORM} -- skipping verification"; return; }

    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL="$(sha256sum "$TMPFILE" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL="$(shasum -a 256 "$TMPFILE" | awk '{print $1}')"
    else
        warn "sha256sum/shasum not found -- skipping checksum verification"
        return
    fi

    if [ "$ACTUAL" = "$EXPECTED" ]; then
        info "Checksum verified"
    else
        die "Checksum mismatch! expected: $EXPECTED  got: $ACTUAL"
    fi
}

# ── install ───────────────────────────────────────────────────────────────────
install_binary() {
    TMPFILE="$1"
    INSTALL_DIR="${PREFIX}/bin"
    DEST="${INSTALL_DIR}/${BINARY}"

    # Try without sudo first
    if mkdir -p "$INSTALL_DIR" 2>/dev/null && mv "$TMPFILE" "$DEST" 2>/dev/null; then
        success "Installed dsd ${VERSION} -> ${DEST}"
        return
    fi

    # Fall back to sudo
    info "Installing to ${DEST} (requires sudo)..."
    sudo mkdir -p "$INSTALL_DIR"
    sudo mv "$TMPFILE" "$DEST"
    sudo chmod +x "$DEST"
    success "Installed dsd ${VERSION} -> ${DEST}"
}

# ── verify install ────────────────────────────────────────────────────────────
verify_install() {
    if command -v dsd >/dev/null 2>&1; then
        DSD_VER="$(dsd version 2>/dev/null | head -1 || true)"
        success "dsd is ready${DSD_VER:+: $DSD_VER}"
        printf '\n  Quick start:\n'
        printf '    dsd health          # instant server health snapshot\n'
        printf '    dsd health deep     # full deep analysis\n'
        printf '    dsd timeline        # incident timeline (last 1h)\n'
        printf '    dsd --help          # all commands\n\n'
    else
        warn "${PREFIX}/bin is not in your PATH."
        printf '  Add to your shell profile:\n'
        printf '    export PATH="$PATH:%s/bin"\n' "${PREFIX}"
    fi
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
    # Allow pinning: install.sh v0.6.0
    if [ -n "$1" ] && [ "$(echo "$1" | cut -c1)" = "v" ]; then
        VERSION="$1"
        PREFIX="${2:-/usr/local}"
    else
        PREFIX="${1:-/usr/local}"
    fi

    printf '\n'
    info "DashDiag (dsd) installer"

    detect_platform
    [ -n "$VERSION" ] || fetch_latest_version
    info "Version: ${VERSION}  Platform: ${PLATFORM}  Prefix: ${PREFIX}"

    TMPFILE="$(download)"
    verify_checksum "$TMPFILE"
    install_binary "$TMPFILE"
    verify_install

    rm -rf "$TMPDIR" 2>/dev/null || true
}

main "$@"
