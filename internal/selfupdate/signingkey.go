package selfupdate

// MinisignPublicKey is the minisign public key that release artifacts are signed
// with. It is the base64 key line from the project's `minisign.pub`.
//
// EMPTY BY DEFAULT → signature verification is INERT and `dsd update` keeps its
// current behaviour (download + sha256 against the release's checksums.txt). This
// is deliberate: the scaffolding ships dormant, exactly like the Homebrew-tap
// release job, so nothing breaks before a key exists.
//
// To ACTIVATE signing (see docs/RELEASE_SIGNING.md):
//  1. `minisign -G -p minisign.pub -s minisign.key`  (generate the keypair once)
//  2. paste the second line of minisign.pub between the quotes below, and the
//     same line into install.sh's MINISIGN_PUBKEY
//  3. add the secret key as the GitHub Actions secret MINISIGN_SECRET_KEY
//     (+ MINISIGN_PASSWORD if the key is password-protected)
//
// Once non-empty, `dsd update` REQUIRES every release to carry a valid
// checksums.txt.minisig and refuses to update otherwise — fail closed.
const MinisignPublicKey = ""
