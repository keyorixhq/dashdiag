# Linux packages (.deb / .rpm)

`dsd` ships `.deb` and `.rpm` packages built with [nfpm](https://nfpm.goreleaser.com)
from the same CGO-free binaries as every other release artifact — no native toolchain,
no agent, no daemon. The package drops a single binary at `/usr/bin/dsd`.

## Build locally

```sh
brew install nfpm                    # or: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
scripts/build-packages.sh 0.6.1      # version without leading "v"
ls dist/*.deb dist/*.rpm
#   dsd_0.6.1_amd64.deb   dsd-0.6.1-1.x86_64.rpm
#   dsd_0.6.1_arm64.deb   dsd-0.6.1-1.aarch64.rpm
```

The script cross-compiles the linux amd64/arm64 binaries (if not already in `dist/`)
and runs nfpm once per arch × format. `packaging/nfpm/nfpm.yaml` is the single source of
truth for package metadata; the script renders a concrete per-arch config from it.

## Install

```sh
# Debian / Ubuntu
sudo apt install ./dsd_0.6.1_amd64.deb

# RHEL / Alma / Rocky / Fedora
sudo rpm -i dsd-0.6.1-1.x86_64.rpm        # or: sudo dnf install ./dsd-0.6.1-1.x86_64.rpm

dsd --version
```

## Release / repos

On a tag push the `release.yml` workflow builds these packages and attaches them to the
GitHub Release (`scripts/build-packages.sh`). A **self-hosted apt/yum repo** (so users can
`apt install dsd` / `dnf install dsd` directly) is the next tier — not wired yet; for now
the packages are downloadable from the releases page. Official Debian/Fedora inclusion is a
much later, separate effort.
