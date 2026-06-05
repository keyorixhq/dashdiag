# keyorixhq/homebrew-tap

Homebrew tap for [`dsd` (DashDiag)](https://github.com/keyorixhq/dashdiag) —
OBD diagnostics for your Linux server.

## Install

```sh
brew install keyorixhq/tap/dsd
```

(Shorthand for `brew tap keyorixhq/tap && brew install dsd`.)

Works on macOS (arm64 + Intel) and Linux (arm64 + amd64) via Homebrew / Linuxbrew.
The formula installs the prebuilt release binary — no Go toolchain required.

## Upgrade

```sh
brew update && brew upgrade dsd
```

## How this tap is maintained

`Formula/dsd.rb` is **generated**, not hand-edited. It is produced from a published
release's `checksums.txt` by
[`scripts/gen-homebrew-formula.sh`](https://github.com/keyorixhq/dashdiag/blob/main/scripts/gen-homebrew-formula.sh)
in the main repo:

```sh
# in the dashdiag repo, after publishing release vX.Y.Z:
scripts/gen-homebrew-formula.sh X.Y.Z
# then copy packaging/homebrew-tap/ here and push, or let CI do it (see below).
```

The main repo's release workflow can push the regenerated formula here automatically
when the `HOMEBREW_TAP_ENABLED` repo variable is set and a `HOMEBREW_TAP_TOKEN` secret
(a PAT with `contents:write` on this tap) is configured. Until then, update it manually
with the command above.

## Repository layout

This is the content of `packaging/homebrew-tap/` in the main repo, mirrored here so the
tap lives at its required `keyorixhq/homebrew-tap` location. Edit the generator in the
main repo, not the formula here.
