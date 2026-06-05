# Spec — Homebrew tap (`brew install keyorixhq/tap/dsd`)

**Status:** APPROVED, building. From BACKLOG "Package-manager distribution":
*"Homebrew (EASY, do first). A tap with a formula pointing at the GitHub release
tarball + sha256. No review queue, fully in your control, ~1-2h."*

**Correction to docs:** `docs/RELEASE.md` step 5 ("Signs binaries with cosign") and
step 7 ("Updates Homebrew tap") are **aspirational** — `.github/workflows/release.yml`
does neither today (verified). This spec makes the Homebrew claim real and corrects the
doc; cosign stays explicitly marked "not yet wired."

## Goal

Let mac/dev users install and upgrade with `brew install keyorixhq/tap/dsd` instead of
the curl one-liner. High-value for the launch audience (devs on macOS).

## Design

A Homebrew **tap** is its own GitHub repo named `keyorixhq/homebrew-tap` containing
`Formula/dsd.rb`. We do NOT pursue homebrew-core (notability/review). The tap needs no
approval.

The current release uploads **raw binaries** (`dsd-{linux,darwin}-{amd64,arm64}`) +
`checksums.txt` — not tarballs. A Homebrew formula can download a bare binary directly
(no archive needed): set `url` to the asset, `sha256` from `checksums.txt`, and
`bin.install` the downloaded file as `dsd`.

### Formula — `Formula/dsd.rb`

Per-OS / per-arch `url` + `sha256` via `on_macos`/`on_linux` + `on_arm`/`on_intel`.
`version` pinned. `install` renames the single downloaded `dsd-*` binary to `dsd`.
`test` runs `dsd --version` (confirmed: `dsd --version` works; there is no `version`
subcommand). Real v0.6.1 sha256s seeded from the published `checksums.txt`.

### Repo layout (this repo, staged for the tap repo)

```
packaging/homebrew-tap/
  Formula/dsd.rb        # the formula (generated, real sha256)
  README.md             # "brew install keyorixhq/tap/dsd" + how it updates
scripts/gen-homebrew-formula.sh   # regenerate dsd.rb for a given version
```

`packaging/homebrew-tap/` is the **content** to push to `keyorixhq/homebrew-tap`. Kept
in-repo so the formula + generator are versioned with the code that produces them. The
push to the actual tap repo is a one-time `git init`/push by the maintainer (outward
action — not done unattended here).

### Generator — `scripts/gen-homebrew-formula.sh`

`gen-homebrew-formula.sh <version>` (e.g. `0.6.1`):
1. `gh release download v<version> --pattern checksums.txt` (or curl the raw asset).
2. Map each `dsd-<os>-<arch>` → its sha256.
3. Render `Formula/dsd.rb` from a heredoc template with version, URLs, sha256s.
Idempotent; reproduces the committed formula exactly for v0.6.1.

### CI (optional, gated — won't break releases)

Add an `update-tap` job to `release.yml`, **guarded by `if: vars.HOMEBREW_TAP_ENABLED == 'true'`**
so it is a no-op until the maintainer (a) creates `keyorixhq/homebrew-tap`, (b) adds a
`HOMEBREW_TAP_TOKEN` repo secret (PAT with `contents:write` on the tap), and (c) sets the
`HOMEBREW_TAP_ENABLED` repo variable. The job regenerates the formula for the pushed tag
and commits it to the tap repo. Off by default → existing releases are unaffected.

### Doc fix — `docs/RELEASE.md`

- Step 5 (cosign): mark **"NOT YET WIRED — aspirational"** so no one relies on a
  signature that isn't produced.
- Step 7 (Homebrew): replace with the real mechanism — run
  `scripts/gen-homebrew-formula.sh <version>` and push `packaging/homebrew-tap/` to
  `keyorixhq/homebrew-tap` (or enable the gated `update-tap` CI job). Add the
  `cosign verify-blob` example caveat (only valid once signing is actually wired).

### Verification

- `ruby -c Formula/dsd.rb` (syntax) and `brew style Formula/dsd.rb`.
- Local install smoke: `brew install --formula ./packaging/homebrew-tap/Formula/dsd.rb`
  on this Mac (arm64) → `dsd --version` → `brew uninstall dsd`. Downloads the real
  darwin-arm64 asset from the v0.6.1 release (read-only); proves url+sha256+install+test.

### Out of scope

homebrew-core submission, nfpm `.deb`/`.rpm` (next tier), cosign signing itself
(separate task — only the doc honesty fix here), Windows (scoop/winget).
