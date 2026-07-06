# Release Process

## Version Numbering (Semantic Versioning)

```
v<MAJOR>.<MINOR>.<PATCH>

MAJOR — breaking change to CLI interface, JSON schema, or exit codes
MINOR — new command or flag (backward compatible)
PATCH — bug fix or performance improvement
```

## Pre-release Checklist

```bash
make test-all          # all tests pass
make vuln              # no known vulnerabilities
make release           # cross-compile all platforms
./dist/dsd-linux-amd64 health --json | python3 -m json.tool
./dist/dsd-linux-amd64 --version
```

Update `CHANGELOG.md` before tagging.

### Hardware smoke test (real-hardware collectors)

`make test-all` and the JSON check above run on CI / your dev box, where the
hardware collectors (SMART, thermal, battery) return absent/virtual data — so
they can't catch a garbage *value* like the `3491877946276%` wear bug (#J), which
exits 0 and is valid JSON. Run the hardware smoke test against the bare-metal
testbed (PLATFORM_COVERAGE row 19) to assert those collector outputs are *sane*,
not just non-crashing:

```bash
PUSH=1 bash scripts/hardware-smoke.sh     # builds current tree, pushes to .7, asserts
# or, to test the binary already on the box:
bash scripts/hardware-smoke.sh
# override the host:  HW_HOST=root@192.168.10.x bash scripts/hardware-smoke.sh
```

It checks wear% ∈ [0,100], CPU temp plausible, battery% ∈ [0,100], SMART health
present — each a range/presence assertion, so garbage and "couldn't measure" both
fail (they don't pass as OK). **Not a hard CI gate** (the testbed is on the LAN,
not reachable from GitHub Actions, and may be offline). If the box is down, skip
it explicitly and note it in the release — don't let a downed testbed silently
mean "untested hardware paths."

> **Why this stays a live LAN script and isn't a replay-based CI gate** (considered
> 2026-06-26, rejected): a replay bundle would sit in the redundant middle of two
> guards that already exist. The garbage-*value* parsing class (the `3491877946276%`
> wear bug) is already covered in CI by unit tests with the real garbage bytes
> (`heuristics_container_drives_test.go`: 11758 °C, the 0 K sentinel) plus the
> raw-tool fuzz corpus — portable, every PR. A *brand-new* garbage value from a real
> sensor needs live hardware, which only this script can surface. A replay snapshot
> is no better than the unit tests for regressions (also fixed inputs) and can't see
> a new sensor value (also a snapshot), so it adds neither — for the cost of a
> committed binary fixture, CI plumbing, and a health-vs-`dsd hardware` shape
> workaround. Keep both layers: unit/fuzz in CI + this script on real hardware.

## Cutting a Release

```bash
git checkout main
git pull origin main
git tag v1.2.3
git push origin v1.2.3
# CI pipeline triggers automatically
```

The CI pipeline (`.github/workflows/release.yml`) — **what actually runs today**
(updated 2026-07-06, activated in v1.17.2):
1. ✅ Runs full test suite (`go test -race`)
2. ✅ Cross-compiles Linux amd64/arm64 + macOS amd64/arm64
3. ✅ Builds `.deb`/`.rpm` packages and Linux AppImages
4. ✅ Generates an SBOM (`dsd.spdx.json`, via syft) covering the release
5. ✅ Generates SHA256 checksums (`checksums.txt`, now covering every artifact
   above including the SBOM)
6. ✅ Signs `checksums.txt` with minisign (`checksums.txt.minisig`) — see
   `docs/RELEASE_SIGNING.md`. `dsd update`/`install.sh` verify this and fail
   closed on an unsigned or tampered release.
7. ✅ Smoke-tests every artifact in a clean container before publishing
8. ✅ Creates GitHub Release (uploads all of the above)
9. ✅ Attests build provenance (SLSA-style, `actions/attest-build-provenance`,
   no key required) over the binaries/packages/SBOM/checksums
10. ⚙️ Updates the Homebrew tap — **gated/off by default** via the `update-tap`
    job; see "Homebrew tap" below.

cosign was never adopted — minisign (step 6) already fills the
authenticity role, and running both would be redundant, not additive.

## Homebrew tap

Formula source lives in `packaging/homebrew-tap/Formula/dsd.rb`, **generated** from a
release's `checksums.txt` by `scripts/gen-homebrew-formula.sh`:

```bash
scripts/gen-homebrew-formula.sh 1.2.3   # regenerates the formula for v1.2.3
```

Publishing it to the user-facing tap (`brew install keyorixhq/tap/dsd`) requires the
formula to live in a repo named `keyorixhq/homebrew-tap`. Two ways:
- **Manual:** run the generator, then copy `packaging/homebrew-tap/` into that repo and push.
- **Automatic:** the `update-tap` CI job does this on tag push, but only once the
  maintainer (1) creates `keyorixhq/homebrew-tap`, (2) adds a `HOMEBREW_TAP_TOKEN`
  secret (PAT with `contents:write` on the tap), and (3) sets the `HOMEBREW_TAP_ENABLED`
  repo variable to `true`. Until then the job is a no-op and releases are unaffected.

(The release *binaries* are hosted on GitHub at `keyorixhq/dashdiag`; only the brand,
homepage, and tap use the DashDiag / dashdiag.sh identity.)

## Verifying a Release (user-facing)

```bash
# Integrity: does the binary match what the release claims to contain?
sha256sum --check --ignore-missing checksums.txt

# Authenticity: was checksums.txt actually signed by the maintainer?
# (full walkthrough + the public key: docs/RELEASE_SIGNING.md)
minisign -Vm checksums.txt -P "<the MINISIGN_PUBKEY line>"

# Provenance: was this exact file built by this exact CI run from this exact
# tagged commit? (no key required, uses GitHub's own attestation)
gh attestation verify dsd-linux-amd64 --owner keyorixhq
```

An SBOM (`dsd.spdx.json`, SPDX format) is attached to every release too, for
license/dependency review — it's checksummed and signed/attested the same as
every other artifact above.

## Updating dsd (user-facing)

`dsd` is a single self-contained binary. There is no package database to migrate and
no daemon to restart -- updating means replacing the binary.

**Re-run the installer (recommended).** The install script always fetches the *latest*
GitHub release, verifies its checksum, and overwrites the existing binary in place:

```bash
curl -fsSL https://dashdiag.sh/install.sh | sh
```

Running it again on an already-installed machine upgrades it. Pin a specific version
(or downgrade) by passing a tag:

```bash
curl -fsSL https://dashdiag.sh/install.sh | sh -s -- v0.6.1
```

**Manual update (no curl-pipe-sh).** For users who won't pipe a remote script to a
shell (common among the security-conscious SRE/sysadmin audience): download the binary
and `checksums.txt` for your platform from the
[GitHub releases page](https://github.com/keyorixhq/dashdiag/releases), verify, and
replace the binary:

```bash
sha256sum --check --ignore-missing checksums.txt
sudo mv dsd-linux-amd64 /usr/local/bin/dsd && sudo chmod +x /usr/local/bin/dsd
```

**Checking your version:** `dsd --version`.

> **`dsd update` (self-update).** `dsd update` checks the latest GitHub release,
> downloads the platform binary, verifies its sha256 against `checksums.txt`, and
> atomically replaces the running binary. A passive "newer version available" nudge
> runs on interactive health runs (disable with `DSD_NO_UPDATE_CHECK=1`). Re-running
> the installer remains an equally supported update path.

## Hotfix Procedure

```bash
git checkout -b hotfix/v1.2.4 v1.2.3
# make the fix
git commit -m "fix: describe the fix"
make test-all
git tag v1.2.4
git push origin v1.2.4
# merge back to main
git checkout main && git merge hotfix/v1.2.4 && git push
```

## CHANGELOG Format

```markdown
## [v1.3.0] — 2026-05-01

### Added
- `--since-deploy` flag: changes since last service restart

### Fixed
- Network collector panic when interface has no IPv4 (#42)

### Breaking Changes
- None
```
