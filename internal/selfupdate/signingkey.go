package selfupdate

// MinisignPublicKey is the minisign public key that release artifacts are signed
// with. It is the base64 key line from the project's `minisign.pub`.
//
// Active (see docs/RELEASE_SIGNING.md). Now that this is non-empty,
// `dsd update` REQUIRES every release to carry a valid checksums.txt.minisig and
// refuses to update otherwise — fail closed. The corresponding private key lives
// only as the GitHub Actions secrets MINISIGN_SECRET_KEY / MINISIGN_PASSWORD,
// consumed by the signing step in .github/workflows/release.yml.
//
// Rotation: generate a new keypair, replace the line below and install.sh's
// MINISIGN_PUBKEY, and update the two GitHub secrets — then cut a release.
const MinisignPublicKey = "RWQizEodTN8n2wK3eKHLT4lSwCbtKxXvMbzGXV4A7xhvhrVS4vucCljR"
