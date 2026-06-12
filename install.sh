#!/bin/sh
# DashDiag (dsd) installer
# Usage: curl -fsSL https://raw.githubusercontent.com/keyorixhq/dashdiag/main/install.sh | sh
# Or:    curl -fsSL https://raw.githubusercontent.com/keyorixhq/dashdiag/main/install.sh | sh -s -- --prefix /usr/local
#
# Integrity: the downloaded binary is sha256-verified against the release's
# checksums.txt and the install FAILS CLOSED if it cannot verify (no checksums,
# no entry for this platform, or no hashing tool). Pass --no-verify to override
# (installs UNVERIFIED — not recommended).

set -e

REPO="keyorixhq/dashdiag"
BINARY="dsd"
# PREFIX / VERSION are parsed from args in main().
# Pinned minisign public key (the base64 line from minisign.pub). EMPTY = release
# signing not yet configured → signature verification is inert. Keep in sync with
# internal/selfupdate MinisignPublicKey. See docs/RELEASE_SIGNING.md.
MINISIGN_PUBKEY=""

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'
# All log output goes to stderr so that command substitution capturing a
# function's stdout (e.g. TMPFILE="$(download)") gets ONLY the intended return
# value, not log lines. (Bug: info() on stdout leaked into $TMPFILE, so the
# checksum step hashed a non-existent path and the install aborted.)
info()    { printf "${BOLD}[dsd]${RESET} %s\n" "$*" >&2; }
success() { printf "${GREEN}✅ %s${RESET}\n" "$*" >&2; }
warn()    { printf "${YELLOW}⚠️  %s${RESET}\n" "$*" >&2; }
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

# Called when integrity verification CANNOT proceed (no checksums.txt, no entry
# for this platform, no hashing tool). Fails CLOSED by default — refuses to
# install a binary it couldn't verify — because an origin that simply withholds
# checksums.txt must not silently downgrade the install to unverified (threat
# model CLI F-3). --no-verify is the explicit, loud escape hatch.
# NOTE: a checksum *mismatch* is positive evidence of tampering, not an inability
# to verify, so it always dies regardless of --no-verify.
unverified() {
    if [ "$NO_VERIFY" = "1" ]; then
        warn "$1 -- continuing anyway (--no-verify: UNVERIFIED install)"
        return 0
    fi
    die "$1. Refusing to install an unverified binary -- re-run with --no-verify to override."
}

# ── verify checksum ──────────────────────────────────────────────────────────
verify_checksum() {
    TMPFILE="$1"
    SUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
    SUMS_FILE="${TMPDIR}/checksums.txt"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$SUMS_URL" -o "$SUMS_FILE" 2>/dev/null || { unverified "Could not fetch checksums.txt from the release"; return; }
    else
        wget -qO "$SUMS_FILE" "$SUMS_URL" 2>/dev/null || { unverified "Could not fetch checksums.txt from the release"; return; }
    fi

    EXPECTED="$(grep "${BINARY}-${PLATFORM}" "$SUMS_FILE" | awk '{print $1}')"
    [ -n "$EXPECTED" ] || { unverified "No checksum for ${BINARY}-${PLATFORM} in checksums.txt"; return; }

    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL="$(sha256sum "$TMPFILE" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL="$(shasum -a 256 "$TMPFILE" | awk '{print $1}')"
    else
        unverified "Neither sha256sum nor shasum is available to compute the hash"
        return
    fi

    if [ "$ACTUAL" = "$EXPECTED" ]; then
        info "Checksum verified"
    else
        die "Checksum mismatch! expected: $EXPECTED  got: $ACTUAL"
    fi
}

# ── verify signature (best-effort authenticity) ───────────────────────────────
# Authenticity layer on top of the checksum (integrity): a minisign signature
# over checksums.txt that a compromised origin can't forge. Inert until a key is
# pinned. Best-effort in shell — needs the `minisign` tool, which most boxes lack;
# the in-binary `dsd update` verifier is the always-on, fail-closed path. A
# signature that is present AND verifiable-as-bad aborts; a missing signature or
# missing tool only warns (the checksum already guaranteed integrity).
verify_signature() {
    [ -n "$MINISIGN_PUBKEY" ] || return 0          # signing not configured — inert
    [ -f "$SUMS_FILE" ] || return 0                # no checksums.txt to verify against

    SIG_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt.minisig"
    SIG_FILE="${SUMS_FILE}.minisig"                # minisign -Vm looks for <file>.minisig
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$SIG_URL" -o "$SIG_FILE" 2>/dev/null || { warn "no release signature found -- verified checksum only"; return 0; }
    else
        wget -qO "$SIG_FILE" "$SIG_URL" 2>/dev/null || { warn "no release signature found -- verified checksum only"; return 0; }
    fi

    if ! command -v minisign >/dev/null 2>&1; then
        warn "release signature present but 'minisign' is not installed -- verified checksum only (to verify authenticity: minisign -Vm checksums.txt -P '$MINISIGN_PUBKEY')"
        return 0
    fi

    if minisign -Vm "$SUMS_FILE" -P "$MINISIGN_PUBKEY" >/dev/null 2>&1; then
        info "Signature verified (minisign)"
    else
        die "Release signature verification FAILED -- refusing to install (possible tampering)"
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
        # $PATH is meant to stay literal here — it's a line the user pastes into their shell.
        # shellcheck disable=SC2016
        printf '    export PATH="$PATH:%s/bin"\n' "${PREFIX}"
    fi
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
    # Arg forms (all back-compat):
    #   --prefix DIR / --prefix=DIR   install root (the documented flag, header line 4)
    #   vX.Y.Z                        pin a release (positional, leading 'v' + digit)
    #   DIR                           bare positional install root
    #   --no-verify                   install even if integrity can't be verified
    VERSION=""
    PREFIX=""
    NO_VERIFY=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --prefix)    [ -n "$2" ] || die "--prefix requires a directory"; PREFIX="$2"; shift 2 ;;
            --prefix=*)  PREFIX="${1#--prefix=}"; shift ;;
            --no-verify) NO_VERIFY=1; shift ;;
            v[0-9]*)     VERSION="$1"; shift ;;
            -*)          die "Unknown option: $1" ;;
            *)           PREFIX="$1"; shift ;;
        esac
    done
    PREFIX="${PREFIX:-/usr/local}"

    printf '\n'
    info "DashDiag (dsd) installer"

    detect_platform
    [ -n "$VERSION" ] || fetch_latest_version
    info "Version: ${VERSION}  Platform: ${PLATFORM}  Prefix: ${PREFIX}"

    TMPFILE="$(download)"
    verify_checksum "$TMPFILE"
    verify_signature
    install_binary "$TMPFILE"
    verify_install

    rm -rf "$TMPDIR" 2>/dev/null || true
}

main "$@"
