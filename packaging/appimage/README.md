# dsd AppImage

A single self-contained file that runs `dsd` from anywhere — no install, no
package manager, no root. Built by `scripts/build-appimage.sh` and attached to
every GitHub release (`dsd-<version>-x86_64.AppImage`, `-aarch64.AppImage`).

## Why this exists

The Steam Deck and every SteamOS device ship an **immutable, read-only rootfs**:

- `/usr` is read-only; `pacman` is disabled.
- Anything dropped in `/usr/local/bin` is **wiped on the next OS update**.
- `sudo steamos-readonly disable` only unlocks temporarily; updates re-lock it.

An AppImage sidesteps all of that — it lives in `$HOME` and survives every
update. This is the install path behind the SteamOS viral-channel strategy It also gives every other Linux distro a
zero-dependency "download and run" option.

## Usage

```bash
curl -L https://dashdiag.sh/dsd.AppImage -o ~/dsd && chmod +x ~/dsd
~/dsd health
```

`dsd` is a static CGO-free binary, so the AppImage is a thin wrapper with no
bundled libraries. `AppRun` does **not** mangle the environment — `dsd` reads
the host's real `/proc` and `/sys`, so it must run against the host namespaces,
not a sandboxed view (this is why dsd is shipped as an AppImage and not a
Flatpak, whose sandbox blocks `/proc`/`/sys`).

If your system lacks FUSE, run it extracted:

```bash
~/dsd --appimage-extract-and-run health
```

## Building

```bash
scripts/build-appimage.sh 0.6.2        # version without leading "v"
```

Cross-builds both arches from one host: `appimagetool` runs on the host arch but
embeds the *target* runtime via the `ARCH` env var, so an x86_64 runner emits the
aarch64 AppImage too. `appimagetool` is auto-downloaded to `dist/.appimagetool/`
and run extracted (no FUSE needed).
