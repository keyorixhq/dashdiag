# Release signing (minisign)

DashDiag releases can be cryptographically signed so that `dsd update` and the
install one-liner verify a release was published by the project — not just that it
downloaded intact. This closes the **single-origin gap**: a compromised or
MITM'd release origin can serve a tampered binary *and* a matching
`checksums.txt`, but it cannot forge an Ed25519 signature without the secret key.

We use [minisign](https://jedisct1.github.io/minisign/): tiny single-file
signatures, no transparency log, no online service — it fits DashDiag's no-cloud,
air-gapped-friendly ethos. The self-updater verifies the signature **in-binary**
(`internal/selfupdate/minisign.go`, stdlib + `x/crypto/blake2b` only), so no
external tool is required on the host.

## Status: scaffolded, dormant

The whole path ships **inert** until a maintainer generates a key — exactly like
the Homebrew-tap release job. With no key configured:

- `internal/selfupdate.MinisignPublicKey == ""` → `dsd update` keeps its current
  behaviour (download + sha256 against `checksums.txt`).
- `install.sh`'s `MINISIGN_PUBKEY=""` → the installer's signature step is skipped.
- the release workflow's `SIGN` env is `false` → the signing step is skipped.

Nothing breaks before a key exists.

## Activating (maintainer, one time)

1. **Generate the keypair** (keep `minisign.key` offline and backed up; never
   commit it):

   ```sh
   minisign -G -p minisign.pub -s minisign.key
   ```

   `minisign.pub` is two lines: a comment and the base64 **public key line**.

2. **Embed the public key** (the base64 line, *not* the comment) in two places —
   they must match:

   - `internal/selfupdate/signingkey.go` → `const MinisignPublicKey = "<line>"`
   - `install.sh` → `MINISIGN_PUBKEY="<line>"`

3. **Add the secret key to GitHub Actions** as repository secrets:

   - `MINISIGN_SECRET_KEY` — the full contents of `minisign.key`
   - `MINISIGN_PASSWORD` — the key's password (omit/empty if you generated it
     with `-W`, passwordless)

4. Cut a release. The workflow signs `checksums.txt` → `checksums.txt.minisig`
   and attaches it. From then on every release is signed, and `dsd update`
   **requires** a valid signature (fail closed).

> Rotation: replace the public key in both files and the `MINISIGN_SECRET_KEY`
> secret, then cut a release. Binaries built with the old key won't auto-update
> across the rotation boundary — document a manual re-install for that hop.

## How verification works

| Path | Verifier | On failure |
|---|---|---|
| `dsd update` | in-binary (`verifyMinisign`), always on once a key is embedded | **aborts the update** (fail closed); a release with no `.minisig` is also refused |
| `install.sh` | the `minisign` tool if present (best-effort) | aborts on a *bad* signature; only warns if the tool or signature is absent (the checksum already guaranteed integrity) |

The signature covers `checksums.txt`; the per-artifact sha256 in that file then
covers each binary. Authenticity (signature) + integrity (hash).

## Verifying a release by hand

```sh
# fetch the artifacts for a release
ver=v0.8.7
base="https://github.com/keyorixhq/dashdiag/releases/download/$ver"
curl -fsSLO "$base/checksums.txt"
curl -fsSLO "$base/checksums.txt.minisig"

# verify the signature with the project's public key
minisign -Vm checksums.txt -P "<the MINISIGN_PUBKEY line>"

# then verify your downloaded binary against the now-trusted checksums
sha256sum -c checksums.txt --ignore-missing
```

A `Signature and comment signature verified` line means `checksums.txt` is
authentic; the `sha256sum -c` step then confirms your binary matches it.
