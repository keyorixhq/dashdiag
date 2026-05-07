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
