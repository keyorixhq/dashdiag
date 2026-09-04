# Threat Model

This document covers the trust boundaries in dsd where external or
attacker-influenceable data crosses into dsd's own code — as opposed to the
collectors, which are covered by the "false-OK" correctness-bug sweeps
tracked in `BUGS.md`. It is scoped to five surfaces, chosen because they are
the only places dsd processes data it did not itself just read live off the
local host:

1. Bundle ingestion (`dsd replay`, `dsd diff`, `dsd migrate certify`)
2. Capture sanitization (`dsd capture --sanitize`, `dsd sanitize`, `--identifiers`)
3. The self-updater and release-signing chain (`dsd update`)
4. Fleet host validation (`dsd fleet`)
5. MCP tool path arguments (`dsd mcp`)

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
  (`maxUntarTotalBytes`, 2 GiB — sized for disk extraction, where each entry
  is written to a temp file and released); `FromSnapshot` (`snapshot.go`'s
  `fromSnapshotWithLimits`) enforces matching per-file and entry-count caps,
  plus its own, deliberately smaller total-bytes bound
  (`maxSnapshotIngestBytes`, 256 MiB) rather than reusing `maxUntarTotalBytes`
  — `FromSnapshot` never touches disk, so every ingested entry's content is
  held in memory for the returned `Bundle`'s lifetime, and the disk-sized
  bound would let a crafted snapshot hold up to 2 GiB in RAM rather than just
  spike briefly during extraction. This doc previously (incorrectly) claimed
  neither path had a size bound, then (still incorrectly, after a partial
  correction) claimed `FromSnapshot` lacked the entry-count/total-bytes caps
  `untarGz` already had — both are fixed as of 2026-08-21's adversarial
  untrusted-input review: `LoadTarball`'s caps are fuzz-verified
  (`FuzzLoadTarball`, ~42k local execs, no failures); `FromSnapshot`'s caps
  are unit-boundary-tested
  (`TestFromSnapshotWithLimits_EntryCountCapped`/`TotalBytesCapped`) but not
  yet covered by a dedicated fuzz target.
- **The fallback from `LoadTarball` to `FromSnapshot` can no longer defeat
  the caps above.** `cmd/replay.go`'s `loadBundle` used to discard
  `LoadTarball`'s error unconditionally and fall back to `FromSnapshot` on
  ANY failure — including `LoadTarball`'s own hostile-input rejections. Before
  `FromSnapshot` had breadth caps of its own (the bullet above), that
  fallback fully defeated `LoadTarball`'s protection for a rejected archive;
  even after `FromSnapshot` gained matching caps, the fallback still
  bypassed `LoadTarball`'s checks for no reason other than a swallowed error.
  Fixed 2026-08-21: `internal/source` now distinguishes `ErrNotNativeBundle`
  ("this isn't our format, try a different parser" — the only signal
  `loadBundle` treats as license to fall back) from `ErrRejected`
  ("recognised as/resembling our format but refused for tripping a limit" —
  propagated as a real failure, never retried against a less-defended
  parser). See `internal/source/source.go`'s sentinel doc comments and
  `cmd/replay_loadbundle_test.go`'s regression coverage (confirmed to fail
  against the pre-fix `loadBundle`).

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
(`cmd/capture_raw.go:120` calls `Bundle.Sanitize()` before
`SaveTarball()` at line 127) — there is no window where an unredacted bundle
touches disk. `SaveTarball` writes with mode `0o600`.

**Default:** `--sanitize` defaults to `true` as of the GAP-2 fix
(docs/product-claim-gaps-2026-09-02.md) — a bundle captured with the bare
documented command is redacted by default; `--no-sanitize` opts out for the
case that genuinely needs raw bytes. Before this, the flag defaulted to
`false`, so the common "run the documented command, email the result" path
shipped unredacted by default.

**Assessment:** this surface is already the most mature of the three — it's
explicitly labeled "best-effort" in code and CLI output
(`internal/source/sanitize.go:13-18`), has round-trip tests
(`sanitize_roundtrip_test.go`), and its known gaps are disclosed rather than
silent. The one concrete gap worth a ticket is IPv6 — everything else here is
a documented tradeoff, not an oversight. One real (non-tradeoff) gap was found
and fixed alongside the default flip: the line-scan regex pass ran on raw JSON
text BEFORE the JSON-structural pass, so a single-line JSON array element
whose string VALUE was itself "KEY=SECRET"-shaped (e.g. a container's `Env`
array entry) could have its value-match swallow the JSON's own closing quote/
bracket, corrupting the document — silently dropping a container from a
collector's parsed result on replay. Caught by a capture→sanitize→replay-both
equivalence test against a real host, not by reasoning about the regex; fixed
by trying the structural pass first and using it exclusively whenever the
document parses.

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

## 4. Fleet host validation — `dsd fleet`

**What crosses the boundary:** a list of host tokens, typically from
`--hosts-file` — a file that may be checked into a shared repo, generated
from inventory tooling, or otherwise assembled by someone other than the
operator running `dsd fleet` at that moment. `internal/fleet.ValidateHost`
is what stands between that list and `exec.CommandContext("ssh"/"scp", ...)`.

**Stated trust assumption today:** each line is a hostname the operator (or
their inventory system) named. The realistic adversarial case isn't a
malicious operator — it's a poisoned line in a shared file that a legitimate
operator runs without inspecting every entry.

**What's mitigated:**
- **Option injection** — a host starting with `-` (e.g.
  `-oProxyCommand=...`) would be parsed by ssh as a flag, not a hostname,
  yielding local command execution. Rejected outright, and `sshRun`/`scp`
  additionally pass `--` before the host argument as defense in depth.
- **scp local/remote path confusion (found 2026-09, adversarial code
  review, reproduced live).** `ValidateHost` previously allowed both `/` and
  a bare `:` in a host token. scp resolves local-vs-remote by scanning its
  destination argument left-to-right for the first `:`; a `/` before that
  point forces a LOCAL-path interpretation regardless of what follows. A
  host of `/tmp/evil` therefore made `scp` silently copy the trusted binary
  onto the *orchestrating* machine instead of any remote host — no network
  call, no error, a deploy that just quietly went nowhere. Worse: because
  the FIRST `:` wins, a host of `attacker.com:/tmp/x` turned the destination
  `host+":"+remotePath` into `attacker.com:/tmp/x:/opt/dsd/dsd-fleet` — scp
  uploaded to `attacker.com`, a host the operator never listed, from one
  poisoned line in a `--hosts-file`. **Fixed:** `ValidateHost` now parses
  `[user@]host` structurally instead of via a character allowlist — `/` is
  rejected outright, and a bare `:` is only accepted inside a bracketed
  IPv6 literal (`[2001:db8::1]`, optionally with a `%zone`, validated via
  `net/netip`), the one shape scp itself expects for IPv6. `scp()` also
  re-checks host for `/` and a bare `:` immediately before building the
  destination string, so a future change to `ValidateHost`'s grammar can't
  silently reopen this gap without an immediate, loud failure at the one
  place the unsafe string would otherwise get built.
- **Remote command injection** — `validateRemoteCmd` rejects shell
  metacharacters in `--remote-cmd` before it's handed to the remote shell.
- **Host key trust** — fleet does not override `StrictHostKeyChecking`
  unless the operator opts in (`AcceptNewHostKeys`); by default it falls
  through to the operator's own `~/.ssh/config`.

**Residual gaps:** none identified. The character-allowlist shape that
produced the scp defect is gone — every character-level exception (`/`, a
bare `:`, `-oProxyCommand=`) is now a structural rejection rather than an
allowlist gap waiting to be found the same way this one was.

## 5. MCP out_path — `dsd mcp`

**What crosses the boundary:** `out_path`/`bundle_path`/`baseline_path`/
`current_path` arguments to the four MCP tools (`dsd_capture`, `dsd_replay`,
`dsd_diff`), validated by `cmd/mcp.go`'s `safeBundlePath`.

**Stated trust assumption before this fix:** "MCP is stdio-only and the
caller is a trusted local process" — true of the transport, but the
assumption was extended to the tool ARGUMENTS too: any absolute or relative
path was allowed, the only rejection was a `..` traversal component. Closed
WONT_FIX under that reasoning (cmd-09-02, 2026-08).

**Why the assumption didn't hold (found 2026-09, revisited):** in agentic
use, `out_path` is not operator-typed — it's LLM-generated from whatever
context the model has read that session, which can include prompt-injected
content from a document, a web page, or output from another tool the agent
ran. The transport being trusted-local doesn't make the argument
operator-chosen. Treating an LLM-generated path as trustworthy as a
human-typed one made `out_path` an arbitrary-file-write primitive (and
`bundle_path`/`baseline_path`/`current_path` an arbitrary-file-read one)
steerable by any document the agent happened to ingest, not by the person
running the agent.

**Fixed:** `safeBundlePath` now constrains every path to resolve under the
MCP server's current working directory by default — the same directory tree
the agent's other file tools (read, write, edit) can already reach, so this
doesn't grant a steered path any capability beyond what the agent's ordinary
toolset already has. `--allow-absolute-paths` (a `dsd mcp` startup flag, not
a per-call argument — a deliberate, human-set choice, not something a
tool-call argument can flip) restores the old unconstrained behavior for
operators who want it, e.g. a fixed capture-archive directory outside the
project tree. The `..`-traversal rejection is unconditional in both modes.

**Residual gaps:** an operator who runs `dsd mcp --allow-absolute-paths`
restores the full original risk — an explicit, documented opt-out, not a
silent one. `bundle_path`/`baseline_path`/`current_path` (the read side) get
the same CWD constraint as `out_path` (the write side) for consistency, even
though an arbitrary-file-read is lower severity than an arbitrary-file-write
— reading `/etc/shadow`'s content into a tool response an agent might then
echo back is still a real disclosure risk, not just a defensive-symmetry
choice.

## Known documentation drift found while researching this doc

`SECURITY.md`'s "Verifying a Release" section told users to run
`cosign verify-blob` — but `docs/RELEASE.md:88` records that cosign was never
adopted; minisign (this doc's §3) has filled that role since v1.17.2.
`SECURITY.md`'s "Threat Model" section also didn't mention the replay/diff/
migrate/sanitize/self-update surfaces at all (its `--share` line was still
accurate — that flag genuinely isn't implemented yet, per `PRIVACY.md`).
Both gaps are now fixed in `SECURITY.md`, which links here for detail.
