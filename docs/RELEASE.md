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

## Cutting a Release

```bash
git checkout main
git pull origin main
git tag v1.2.3
git push origin v1.2.3
# CI pipeline triggers automatically
```

The CI pipeline (`.github/workflows/release.yml`):
1. Runs full test suite
2. Cross-compiles Linux amd64/arm64 + macOS amd64/arm64
3. Generates SHA256 checksums
4. Generates SBOM with syft
5. Signs binaries with cosign
6. Creates GitHub Release
7. Updates Homebrew tap

## Verifying a Release (user-facing)

```bash
cosign verify-blob \
  --key https://raw.githubusercontent.com/keyorixhq/dashdiag/main/cosign.pub \
  --signature dsd-linux-amd64.sig \
  dsd-linux-amd64

sha256sum --check --ignore-missing checksums.txt
```

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

> **Planned (not yet shipped):** a `dsd update` self-update subcommand and a passive
> "newer version available" nudge are recorded as backlog candidates (gated, see
> BACKLOG.md). Until then, re-running the installer is the supported update path.

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
