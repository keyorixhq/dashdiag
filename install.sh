#!/bin/sh
# shellcheck disable=SC3043  # local is used intentionally; widely supported by ash/dash/busybox sh
# DashDiag (dsd) installer
# Usage: curl -fsSL https://raw.githubusercontent.com/keyorixhq/dashdiag/main/install.sh | sh
# Or:    curl -fsSL https://raw.githubusercontent.com/keyorixhq/dashdiag/main/install.sh | sh -s -- --prefix /usr/local
#
# Integrity: the downloaded binary is sha256-verified against the release's
# checksums.txt and the install FAILS CLOSED if it cannot verify (no checksums,
# no entry for this platform, or no hashing tool). Pass --no-verify to override
# (installs UNVERIFIED — not recommended).
#
# Authenticity: when the `minisign` tool is available, checksums.txt's release
# signature is also checked (best-effort by default — most boxes lack
# minisign, so a missing tool or signature only warns). Pass
# --require-signature to fail closed instead, holding the initial install to
# the same standard `dsd update` always enforces.

set -e

# Search trusted system directories FIRST, regardless of what the invoking
# shell's PATH contains -- mirrors internal/source/trustedexec.go's Go-side
# hardening (ResolveTrustedTool) for the same reason: this script is commonly
# piped into `sh` right before install_binary's sudo fallback, so a directory
# writable by another unprivileged local user that got prepended ahead of the
# real system dirs (a tampered shell profile, a leftover sudo environment, a
# misconfigured CI/cron PATH) could otherwise substitute a malicious curl,
# mktemp, mv, or sudo for every bare-name tool this script invokes. Prepending
# (not replacing) keeps any less-common tool this script doesn't pin -- none,
# currently, but future-proof -- resolvable from the rest of the inherited
# PATH.
PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin:/opt/homebrew/bin:/opt/homebrew/sbin:${PATH}"
export PATH

REPO="keyorixhq/dashdiag"
BINARY="dsd"
# PREFIX / VERSION are parsed from args in main().
# Pinned minisign public key (the base64 line from minisign.pub). Active —
# keep in sync with internal/selfupdate MinisignPublicKey. See docs/RELEASE_SIGNING.md.
MINISIGN_PUBKEY="RWQizEodTN8n2wK3eKHLT4lSwCbtKxXvMbzGXV4A7xhvhrVS4vucCljR"

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
    _url="https://api.github.com/repos/${REPO}/releases/latest"
    # GITHUB_TOKEN (if set) avoids rate-limit 403s on shared CI runner IPs.
    # --retry 3 --retry-delay 5: curl retries natively on HTTP 5xx (incl. 503)
    # and on network errors; covers transient GitHub API / CDN hiccups.
    if command -v curl >/dev/null 2>&1; then
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            VERSION="$(curl -fsSL --retry 3 --retry-delay 5 --proto '=https' --proto-redir '=https' -H "Authorization: token ${GITHUB_TOKEN}" "$_url" \
                | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
        else
            VERSION="$(curl -fsSL --retry 3 --retry-delay 5 --proto '=https' --proto-redir '=https' "$_url" \
                | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            # NOSONAR -- shelldre:S6506: GitHub releases CDN uses HTTP 302 redirects; --https-only already mitigates open-redirect risk
            VERSION="$(wget -qO- --https-only --header="Authorization: token ${GITHUB_TOKEN}" "$_url" \
                | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
        else
            # NOSONAR -- shelldre:S6506: same
            VERSION="$(wget -qO- --https-only "$_url" \
                | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
        fi
    else
        die "curl or wget is required"
    fi
    unset _url

    [ -n "$VERSION" ] || die "Could not determine latest version from GitHub"
    # Same shape check main() applies to a user-supplied vX.Y.Z argument
    # (case "$1" in v[0-9]*) -- the value here comes from a JSON field
    # extracted with grep/sed rather than a shell case match, so validate
    # it explicitly before it's spliced into download URLs below.
    case "$VERSION" in
        v[0-9]*) ;;
        *) die "Unexpected version format from GitHub API: '$VERSION'" ;;
    esac
}

# ── download ─────────────────────────────────────────────────────────────────
# WORK_DIR must already be set by the caller (main(), before this is invoked
# via `TMPFILE="$(download)"`) -- NOT created in here. `$(...)` command
# substitution runs the function in a SUBSHELL, so a `WORK_DIR="$(mktemp -d)"`
# assigned inside download() would vanish the instant download() returns,
# leaving every later WORK_DIR-relative path (verify_checksum's SUMS_FILE,
# verify_signature's SIG_FILE, the EXIT trap's cleanup) resolving against an
# EMPTY WORK_DIR -- i.e. the filesystem root -- silently failing every write
# there and forcing every default install into the fail-closed "could not
# verify" path. (Found live on main, 2026-08-25: this broke every `curl | sh`
# install that didn't pass --no-verify.)
download() {
    FILENAME="${BINARY}-${PLATFORM}"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${FILENAME}"
    TMPFILE="${WORK_DIR}/${BINARY}"

    info "Downloading dsd ${VERSION} (${PLATFORM})..."

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 5 --proto '=https' --proto-redir '=https' --progress-bar "$URL" -o "$TMPFILE" || die "Download failed: $URL"
    else
        wget -q --https-only --show-progress "$URL" -O "$TMPFILE" || die "Download failed: $URL" # NOSONAR -- shelldre:S6506
    fi

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
    local msg="$1"
    if [ "$NO_VERIFY" = "1" ]; then
        warn "$msg -- continuing anyway (--no-verify: UNVERIFIED install)"
        return 0
    fi
    die "$msg. Refusing to install an unverified binary -- re-run with --no-verify to override."
}

# ── verify checksum ──────────────────────────────────────────────────────────
verify_checksum() {
    TMPFILE="$1"
    SUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
    SUMS_FILE="${WORK_DIR}/checksums.txt"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 5 --proto '=https' --proto-redir '=https' "$SUMS_URL" -o "$SUMS_FILE" 2>/dev/null || { unverified "Could not fetch checksums.txt from the release"; return; }
    else
        wget -qO "$SUMS_FILE" --https-only "$SUMS_URL" 2>/dev/null || { unverified "Could not fetch checksums.txt from the release"; return; } # NOSONAR -- shelldre:S6506
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

# ── verify signature (best-effort authenticity, or enforced with --require-signature) ──
# Authenticity layer on top of the checksum (integrity): a minisign signature
# over checksums.txt that a compromised origin can't forge. Inert until a key is
# pinned. Best-effort in shell by default — needs the `minisign` tool, which most
# boxes lack; the in-binary `dsd update` verifier is the always-on, fail-closed
# path for later updates. A signature that is present AND verifiable-as-bad
# always aborts; a missing signature or missing tool only warns UNLESS
# --require-signature was passed, in which case both fail closed too — for
# environments (CI, high-trust deployments) that want the initial install held
# to the same standard as `dsd update`.
verify_signature() {
    [ -n "$MINISIGN_PUBKEY" ] || return 0          # signing not configured — inert
    [ -f "$SUMS_FILE" ] || return 0                # no checksums.txt to verify against

    SIG_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt.minisig"
    SIG_FILE="${SUMS_FILE}.minisig"                # minisign -Vm looks for <file>.minisig
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 5 --proto '=https' --proto-redir '=https' "$SIG_URL" -o "$SIG_FILE" 2>/dev/null || { signature_unenforced "no release signature found"; return; }
    else
        wget -qO "$SIG_FILE" --https-only "$SIG_URL" 2>/dev/null || { signature_unenforced "no release signature found"; return; } # NOSONAR -- shelldre:S6506
    fi

    if ! command -v minisign >/dev/null 2>&1; then
        signature_unenforced "release signature present but 'minisign' is not installed (to verify authenticity: minisign -Vm checksums.txt -P '$MINISIGN_PUBKEY')"
        return
    fi

    if minisign -Vm "$SUMS_FILE" -P "$MINISIGN_PUBKEY" >/dev/null 2>&1; then
        info "Signature verified (minisign)"
    else
        die "Release signature verification FAILED -- refusing to install (possible tampering)"
    fi
}

# Called when signature verification could not proceed at all (no minisig
# published, or no minisign tool) — as opposed to a signature that was checked
# and failed, which always dies regardless of this function. Default: warn and
# fall back to checksum-only, since minisign is absent on most boxes and every
# install would otherwise break. --require-signature: die instead, same
# fail-closed contract verify_checksum's unverified() already gives --no-verify's
# opposite number.
signature_unenforced() {
    local msg="$1"
    if [ "$REQUIRE_SIGNATURE" = "1" ]; then
        die "$msg -- refusing to install without a verified signature (--require-signature)."
    fi
    warn "$msg -- verified checksum only"
}

# refuse_symlinked_prefix guards install_binary's mkdir -p step against a
# symlink-follow attack (install-script-02): `mkdir -p` walks and creates
# EVERY missing path component, following any symlink already present along
# the way -- unlike the final `mv "$TMPFILE" "$DEST"` step, which uses
# rename(2) and therefore replaces a destination symlink atomically rather
# than writing through it (that half of the original finding was already
# safe). Under a NON-DEFAULT --prefix whose parent directory is already
# attacker-writable, an attacker could pre-plant PREFIX (or PREFIX/bin) as a
# symlink so `sudo mkdir -p` silently creates real directories -- and the
# eventual sudo-owned $DEST -- somewhere the attacker chose instead, e.g.
# inside another root-owned directory the attacker couldn't otherwise reach.
# The default --prefix (/usr/local, root-owned already) is not exposed to
# this: an unprivileged attacker can't plant a symlink there in the first
# place. -L (not -e) specifically detects "is a symlink", independent of
# whether the link target exists, is a directory, or is dangling.
#
# Residual window (2026-09, code review, PLAUSIBLE not reproduced -- see
# BACKLOG.md): this check-then-act cannot be made fully atomic in portable
# POSIX sh -- there is no atomic "open/create this path only if it isn't a
# symlink" primitive available here. Be honest about what install_binary
# below actually narrows, not eliminates: (a) it re-checks immediately
# before each privileged step rather than once at the top of the function,
# so a swap has to land in one specific gap instead of anywhere across the
# whole install; (b) once INSTALL_DIR is confirmed real, install_binary
# `cd`s into it ONCE and addresses the binary by bare relative name from
# then on -- the shell's cwd is pinned to that directory's inode at cd time,
# so a symlink swap of the INSTALL_DIR *path* after the cd can no longer
# redirect the mv/chmod that follow, unlike re-deriving
# "$INSTALL_DIR/$BINARY" as a fresh path string for each operation (which is
# what this function used to do). The window that remains: between this
# check and the cd. Exploiting it still needs a local attacker, a
# non-default --prefix whose parent directory is already attacker-writable,
# and precise timing; the default --prefix (/usr/local) stays unreachable to
# it, per the paragraph above.
refuse_symlinked_prefix() {
    if [ -L "$PREFIX" ]; then
        die "${PREFIX} is a symlink -- refusing to install through it (possible symlink attack). Pass a real directory via --prefix."
    fi
    if [ -L "$INSTALL_DIR" ]; then
        die "${INSTALL_DIR} is a symlink -- refusing to install through it (possible symlink attack). Pass a real directory via --prefix."
    fi
}

# ── install ───────────────────────────────────────────────────────────────────
install_binary() {
    TMPFILE="$1"
    INSTALL_DIR="${PREFIX}/bin"
    DEST="${INSTALL_DIR}/${BINARY}"
    refuse_symlinked_prefix

    # Try without sudo first. Re-check right before use (see
    # refuse_symlinked_prefix's comment), then resolve INSTALL_DIR once via
    # cd and address the binary by relative name inside it, rather than
    # re-walking "$INSTALL_DIR/$BINARY" as a path string that a symlink swap
    # could have since redirected.
    if mkdir -p "$INSTALL_DIR" 2>/dev/null; then
        refuse_symlinked_prefix
        if ( cd "$INSTALL_DIR" 2>/dev/null && mv "$TMPFILE" "$BINARY" 2>/dev/null ); then
            success "Installed dsd ${VERSION} -> ${DEST}"
            return
        fi
    fi

    # Fall back to sudo. cd/mv/chmod run as a single root-privileged
    # subshell (one sudo invocation, not three) so the same resolve-once
    # pattern holds under root's own privilege too -- root cd's into
    # INSTALL_DIR ONCE, then mv and chmod both address the binary by
    # relative name, closing the gap where the original code re-walked
    # "$DEST" as a fresh path for chmod after already having done so for mv.
    # Positional args, not string interpolation, so none of these values can
    # break out of the inline script even if they contained shell
    # metacharacters.
    info "Installing to ${DEST} (requires sudo)..."
    refuse_symlinked_prefix
    sudo mkdir -p "$INSTALL_DIR"
    refuse_symlinked_prefix
    sudo sh -c 'cd "$1" && mv "$2" "$3" && chmod +x "$3"' _ "$INSTALL_DIR" "$TMPFILE" "$BINARY"
    success "Installed dsd ${VERSION} -> ${DEST}"
}

# ── verify install ────────────────────────────────────────────────────────────
verify_install() {
    # Exec the exact path install_binary just wrote to (DEST), not a
    # PATH-resolved `dsd` -- an earlier or attacker-planted `dsd` earlier on
    # $PATH than ${INSTALL_DIR} would otherwise get reported as proof the
    # install succeeded, even though it's not the binary this script placed.
    if [ -x "$DEST" ]; then
        DSD_VER="$("$DEST" --version 2>/dev/null | head -1 || true)"
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
    #   --require-signature           fail closed if the release signature can't be checked
    VERSION=""
    PREFIX=""
    NO_VERIFY=0
    REQUIRE_SIGNATURE=0
    while [ $# -gt 0 ]; do
        case "$1" in # NOSONAR — shift-loop arg parsing; $1 changes each iteration, local extraction is not applicable
            --prefix)           [ -n "$2" ] || die "--prefix requires a directory"; PREFIX="$2"; shift 2 ;; # NOSONAR
            --prefix=*)         PREFIX="${1#--prefix=}"; shift ;;
            --no-verify)        NO_VERIFY=1; shift ;;
            --require-signature) REQUIRE_SIGNATURE=1; shift ;;
            v[0-9]*)            VERSION="$1"; shift ;;
            -*)                 die "Unknown option: $1" ;; # NOSONAR
            *)                  PREFIX="$1"; shift ;;
        esac
    done
    PREFIX="${PREFIX:-/usr/local}"
    [ "$NO_VERIFY" = "1" ] && [ "$REQUIRE_SIGNATURE" = "1" ] && die "--no-verify and --require-signature are contradictory"

    printf '\n'
    info "DashDiag (dsd) installer"

    detect_platform
    [ -n "$VERSION" ] || fetch_latest_version
    info "Version: ${VERSION}  Platform: ${PLATFORM}  Prefix: ${PREFIX}"

    # WORK_DIR must be created HERE, not inside download() -- download() is
    # invoked via `TMPFILE="$(download)"`, and a subshell-local WORK_DIR would
    # not survive back to this (the real) shell. See download()'s doc comment.
    # Note: intentionally NOT named TMPDIR -- that name would shadow the
    # environment TMPDIR that mktemp itself (and any child process spawned
    # after this point) reads, causing every subsequent temp-file operation in
    # this shell to silently resolve against our just-created directory
    # instead of the real environment setting.
    WORK_DIR="$(mktemp -d)"
    # Register cleanup now, before download() runs, so any subsequent die() or
    # set -e exit (including one from inside download() itself) removes the
    # temp directory rather than leaking it.
    trap 'rm -rf "$WORK_DIR"' EXIT
    TMPFILE="$(download)"
    verify_checksum "$TMPFILE"
    verify_signature
    # Make executable only after checksum (and optional signature) are verified —
    # an unverified binary must never be executable on disk.
    chmod +x "$TMPFILE"
    install_binary "$TMPFILE"
    verify_install
}

main "$@"
