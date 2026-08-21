# Threat Model

This document covers the trust boundaries in dsd where external or
attacker-influenceable data crosses into dsd's own code — as opposed to the
collectors, which are covered by the "false-OK" correctness-bug sweeps
tracked in `BUGS.md`. It is scoped to three surfaces, chosen because they are
the only places dsd processes data it did not itself just read live off the
local host:

1. Bundle ingestion (`dsd replay`, `dsd diff`, `dsd migrate certify`)
2. Capture sanitization (`dsd capture --sanitize`, `dsd sanitize`, `--identifiers`)
3. The self-updater and release-signing chain (`dsd update`)

For each surface: what's trusted today, what's verified, and what residual
risk remains. This is not a full enterprise DFD — dsd is a single static
binary, not a multi-service system — so the exercise is scoped to boundaries
where data actually changes trust level, not every internal function call.

## 1. Bundle ingestion — `dsd replay` / `dsd diff` / `dsd migrate certify`

**What crosses the boundary:** a `.tar.gz` capture bundle, produced by
`dsd capture --raw` on some machine, read back in on possibly a different
machine by a different operator.

**Stated trust assumption today:** ADR-0003 (`docs/adr/0003-raw-input-capture-replay.md`)
says bundles are "trusted-debugging artifacts" — the documented model assumes
the person running `dsd replay` generated or otherwise trusts the bundle.

**In practice this assumption is weaker than the code suggests.** The
capture→sanitize→share workflow (`docs/SHARE_DESIGN.md`) exists specifically
so a customer can hand you a bundle from *their* machine for offline
diagnosis, and `dsd migrate certify` reads a destination-side bundle produced
by a migration the operator doesn't fully control end-to-end. Both are
realistic paths for a bundle authored by someone other than the person
running `dsd replay` — i.e. exactly the case a threat model should assume is
adversarial-adjacent, even if not actively malicious.

**What's already mitigated** (`internal/source/tarball.go`, `internal/source/snapshot.go`):
- Path traversal: entries with `..` or an absolute path are silently
  skipped (`tarball.go:105-112`).
- Symlink/device/hardlink entries: skipped outright — only `tar.TypeReg` is
  extracted.
- Manifest format is checked (`persist.go:164-165`) — an unrecognized
  `Format` string is rejected before the bundle is used.
- **Decompression-bomb / breadth bound on both extraction paths.** `untarGz`
  (`tarball.go`'s `untarGzWithLimits`) caps per-file size (`maxUntarFileSize`),
  entry count (`maxUntarEntries`), and total extracted bytes
  (`maxUntarTotalBytes`); `FromSnapshot` (`snapshot.go`'s
  `fromSnapshotWithLimits`) enforces the same three caps. This doc previously
  (incorrectly) claimed neither path had a size bound, then (still
  incorrectly, after a partial correction) claimed `FromSnapshot` lacked the
  entry-count/total-bytes caps `untarGz` already had — both are fixed as of
  2026-08-21's adversarial untrusted-input review: `LoadTarball`'s caps are
  fuzz-verified (`FuzzLoadTarball`, ~42k local execs, no failures);
  `FromSnapshot`'s caps are unit-boundary-tested
  (`TestFromSnapshotWithLimits_EntryCountCapped`/`TotalBytesCapped`) but not
  yet covered by a dedicated fuzz target.

**Residual gaps:**
- **Manifest fields beyond `Format` are unconstrained strings** (`Host`,
  `OS`, `DistroID`, `Kernel`, `DsdVer`, etc.) — low severity today since
  they're only ever displayed or used for informational branching, but worth
  keeping in mind if a future consumer starts making trust decisions based on
  them.
- **Recorded command/file bytes are replayed verbatim** with no shape
  validation — a collector parser that only sees real tool output today
  would, on replay, see arbitrary bytes a bundle author chose to record. This
  is the same class of bug the fuzzing rig already hunts for on *live* tool
  output (`scripts/fuzz-continuous.sh`); a hostile bundle is just another way
  to reach the same parsers with adversarial input, and the fuzz corpus is
  the right existing tool to extend here rather than building new defenses.

**Recommendation:** add a `FuzzFromSnapshot` target alongside `FuzzLoadTarball`
so `FromSnapshot`'s breadth caps get the same fuzz coverage `LoadTarball`'s do
(currently only unit-tested), and update ADR-0003's trust language to match
how bundles are actually used — replace "trusted-debugging artifact" with an
explicit statement that bundles may arrive from another party and extraction
is hardened accordingly (path/symlink/size), while *contents* (command
output, file contents) are handled by the same parser-hardening effort
already applied to live collector input.

## 2. Capture sanitization — `dsd capture --sanitize` / `dsd sanitize` / `--identifiers`

**What crosses the boundary:** nothing crosses *in* here — this is the
outbound side, redacting a bundle before an operator shares it externally.
Covered because it's the control that's supposed to make surface 1 safe for
the receiving party, so its actual guarantees matter to this doc.

**What's redacted** (`internal/source/sanitize.go:27-50`): PEM private keys,
`password`/`secret`/`token`/`api_key`-shaped assignments, AWS access key IDs,
HTTP bearer tokens, bare JWTs, `/etc/shadow` hashes, URL-embedded passwords,
and (by cache key, not pattern) AWS IMDSv2 tokens. `--identifiers` additionally
hashes IPv4/MAC/hostname to stable placeholders.

**What's explicitly not redacted, by design or known gap:**
- Probe-target IPs (gateway, DNS, NTP) embedded in command-index keys — kept
  on purpose, because replay looks up recorded results by the literal
  command key and redacting them would break replay. Disclosed in code
  comments and CLI output.
- IPv6 addresses — not handled by the current regex, a real gap rather than
  a deliberate tradeoff.
- Disk serial numbers — not handled.

**Timing:** sanitization happens entirely in memory
(`cmd/capture_raw.go:107` calls `Bundle.Sanitize()` before
`SaveTarball()` at line 114) — there is no window where an unredacted bundle
touches disk. `SaveTarball` writes with mode `0o600`.

**Assessment:** this surface is already the most mature of the three — it's
explicitly labeled "best-effort" in code and CLI output
(`internal/source/sanitize.go:10-15`), has round-trip tests
(`sanitize_roundtrip_test.go`), and its known gaps are disclosed rather than
silent. The one concrete gap worth a ticket is IPv6 — everything else here is
a documented tradeoff, not an oversight.

## 3. Self-updater & release-signing chain — `dsd update`

**What crosses the boundary:** a release binary and `checksums.txt` fetched
over the GitHub releases API, verified, then swapped in for the running
binary.

**Chain** (`internal/selfupdate/selfupdate.go`): fetch latest release → download
target binary to a temp file, hashing in-flight (`downloadToTemp`,
lines 301-325) → fetch `checksums.txt` → verify its minisign signature
against the compile-time-embedded public key
(`internal/selfupdate/signingkey.go:14`) → compare the downloaded binary's
hash against the signed checksum → `os.Rename(tmp, exe)`.

**Fail-closed on every path** (`selfupdate.go:194-239`): missing
`checksums.txt.minisig` asset, signature-fetch failure, bad signature, or
checksum mismatch all abort with no replacement of the running binary. There
is no `--skip-verify` flag and no environment override — `DSD_NO_UPDATE_CHECK`
only silences the passive version-nudge, it does not touch the `update`
command's verification path.

**Atomicity:** the temp file is created in the same directory as the target
binary (`selfupdate.go:227`, `os.CreateTemp(dir, ...)`), guaranteeing the
final `os.Rename` is same-filesystem and therefore atomic — no partial-write
window between verification and use.

**Passive nudge reads a cache, and — opt-in only — can refresh it over the
network:** `MaybeNudge()` (`internal/selfupdate/nudge.go`) reads a locally
cached version string and prints a one-line message. If that cache is
missing or older than 24h, it also attempts a single best-effort HTTPS
refresh against `api.github.com` (`RefreshCache` → `LatestRelease`), bounded
to 800ms so an interactive run is never noticeably delayed. That refresh is
gated by the shared `platform.NetworkAllowed()` policy (`internal/platform/
network_policy.go`) — off by default, opt in with `--network`/
`DSD_ALLOW_NETWORK`, hard-overridden off by `DSD_OFFLINE` — in addition to
the nudge-specific `DSD_NO_UPDATE_CHECK`. With network disallowed the nudge
still degrades to the cached-only behavior described above; it never fetches
a binary or executes anything, so it can't be tricked into more than a
misleading version string on stdout.

**Residual risk:** the same one every code-signing scheme has — if the
`MINISIGN_SECRET_KEY` GitHub Actions secret or the maintainer's offline
private key is compromised, a signed-and-legitimate-looking malicious release
is possible. Mitigation here is entirely key-custody discipline (the key was
generated outside any AI-assisted session and stays that way — see
`docs/RELEASE_SIGNING.md`), not a code control, so it's out of scope for this
doc beyond flagging that the whole chain's security rests on that one
offline secret.

**Assessment:** no gaps found in the code path itself. The design is
fail-closed, atomic, and has no bypass surface.

## Known documentation drift found while researching this doc

`SECURITY.md`'s "Verifying a Release" section told users to run
`cosign verify-blob` — but `docs/RELEASE.md:88` records that cosign was never
adopted; minisign (this doc's §3) has filled that role since v1.17.2.
`SECURITY.md`'s "Threat Model" section also didn't mention the replay/diff/
migrate/sanitize/self-update surfaces at all (its `--share` line was still
accurate — that flag genuinely isn't implemented yet, per `PRIVACY.md`).
Both gaps are now fixed in `SECURITY.md`, which links here for detail.
