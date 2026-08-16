// Package selfupdate implements `dsd update` — query the GitHub releases API,
// download the platform binary, verify its sha256 against the release's
// checksums.txt, and atomically replace the running binary. It also backs the
// passive "newer version available" nudge via a TTL-cached check.
//
// Safety: the nudge never blocks the hot path beyond a short timeout, is gated
// to interactive runs, is disabled by DSD_NO_UPDATE_CHECK or DSD_OFFLINE, and
// never nags dev builds. The self-replace is atomic (download to a temp file in
// the target dir, verify, then rename over the running binary).
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repo is the GitHub owner/name the updater talks to.
const Repo = "keyorixhq/dashdiag"

// maxAPIResponseBytes bounds the GitHub releases API JSON response and the
// small release assets (checksums.txt, the .minisig signature) fetched via
// fetchBytes. None of these are legitimately large — a release JSON document
// or a checksums file lists at most a few dozen assets, and a minisig
// signature is a few hundred bytes — so an unbounded read here would let a
// compromised/spoofed response (or a MITM on a downgraded connection) drive
// unbounded memory allocation before any signature/checksum check ever runs.
// Mirrors the same LimitReader-with-slack pattern used by
// share.maxDecodedReportBytes and cvedata.boundDecompressed elsewhere in
// this codebase. The actual platform binary (downloadToTemp) streams
// straight to a temp file on disk rather than into memory, so it uses its
// own larger cap (maxDownloadBytes) instead of this one — disk exhaustion is
// still a real concern there even though nothing is buffered in memory, and
// the sha256 checksum alone doesn't help: that check only runs AFTER the
// full body has already been written to disk.
const maxAPIResponseBytes = 4 << 20 // 4MiB

// maxDownloadBytes bounds the platform binary download in downloadToTemp.
// Released dsd binaries are tens of MB at most; this is generous headroom
// that will never truncate a legitimate release while still aborting a
// runaway or adversarial response before it can exhaust disk space — the
// sha256 checksum check that follows only runs once the full body is
// already on disk, so it can't substitute for a size cap on this path. A
// var (not const), like apiBase/dlClient above, so a test can shrink it
// rather than actually transferring 512MiB over an httptest server.
var maxDownloadBytes int64 = 512 << 20 // 512MiB

// limitedBody wraps r with a cap of maxAPIResponseBytes+1 so a response
// exceeding the limit is distinguishable (via limitCheck) from one that
// legitimately ends exactly at the boundary.
func limitedBody(r io.Reader) io.Reader {
	return io.LimitReader(r, maxAPIResponseBytes+1)
}

// limitExceeded reports whether n bytes read through a limitedBody reader
// hit its cap — i.e. the real response was larger than maxAPIResponseBytes.
func limitExceeded(n int) bool { return n > maxAPIResponseBytes }

// Asset is one file attached to a GitHub release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

// Release is the subset of the GitHub release API we use.
type Release struct {
	TagName string  `json:"tag_name"`
	HTMLURL string  `json:"html_url"`
	Assets  []Asset `json:"assets"`
}

// apiBase / dlClient are overridable in tests.
var (
	apiBase   = "https://api.github.com"
	dlClient  = &http.Client{Timeout: 60 * time.Second}
	apiClient = &http.Client{Timeout: 10 * time.Second}
	// executable resolves the running binary path; overridable in tests.
	executable = os.Executable
	// signingPublicKey is the key Apply() checks releases against; defaults to
	// the build-embedded MinisignPublicKey. Overridable in tests that exercise
	// Apply()'s checksum/download path without also having to forge a real
	// minisign signature for the fake release fixture.
	signingPublicKey = MinisignPublicKey
	osChmod          = os.Chmod
	closeFile        = (*os.File).Close
)

// AssetName is the release asset for the running platform, e.g. dsd-linux-amd64.
func AssetName() string {
	return fmt.Sprintf("dsd-%s-%s", runtime.GOOS, runtime.GOARCH)
}

// LatestRelease fetches the newest published release.
func LatestRelease(ctx context.Context) (*Release, error) {
	url := apiBase + "/repos/" + Repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}
	var rel Release
	if err := json.NewDecoder(limitedBody(resp.Body)).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("release has no tag")
	}
	return &rel, nil
}

// normalize strips a leading "v" and returns "" for non-release versions
// (dev builds, git-describe strings) so they are never treated as comparable.
func normalize(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" || v == "dev" {
		return ""
	}
	// Reject anything that isn't MAJOR.MINOR[.PATCH...] of digits.
	for _, part := range strings.SplitN(v, ".", 3) {
		// allow a trailing pre-release/build suffix on the patch part
		num := part
		if i := strings.IndexAny(part, "-+"); i >= 0 {
			num = part[:i]
		}
		if num == "" {
			return ""
		}
		if _, err := strconv.Atoi(num); err != nil {
			return ""
		}
	}
	return v
}

// CompareVersions returns -1 if a<b, 0 if equal, 1 if a>b (semver-ish, by the
// numeric MAJOR.MINOR.PATCH). Unparseable inputs sort as lowest.
func CompareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := range 3 {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func versionParts(v string) [3]int {
	var out [3]int
	n := normalize(v)
	if n == "" {
		return out
	}
	for i, part := range strings.SplitN(n, ".", 3) {
		num := part
		if j := strings.IndexAny(part, "-+"); j >= 0 {
			num = part[:j]
		}
		out[i], _ = strconv.Atoi(num)
	}
	return out
}

// isCleanRelease reports whether v is a plain release tag (vN.N or vN.N.N, pure
// digits). It rejects dev builds ("dev"), git-describe strings
// ("v0.6.1-12-gabc123"), and pre-release tags ("v1.2.3-rc1") — none of which
// should ever be auto-nagged as "outdated".
func isCleanRelease(v string) bool {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

// IsNewer reports whether latest is a strictly newer release than current.
// Returns false unless BOTH are clean release tags (never nag dev/describe/rc).
func IsNewer(current, latest string) bool {
	if !isCleanRelease(current) || !isCleanRelease(latest) {
		return false
	}
	return CompareVersions(latest, current) > 0
}

// findAsset returns the asset with the given name, or nil.
func findAsset(assets []Asset, name string) *Asset {
	for i := range assets {
		if assets[i].Name == name {
			return &assets[i]
		}
	}
	return nil
}

// Apply downloads the platform binary for rel, verifies its sha256 against the
// release's checksums.txt, and atomically replaces the running executable.
// Returns the path replaced.
func Apply(ctx context.Context, rel *Release) (string, error) {
	name := AssetName()
	bin := findAsset(rel.Assets, name)
	if bin == nil {
		return "", fmt.Errorf("release %s has no asset %q for this platform", rel.TagName, name)
	}
	sums := findAsset(rel.Assets, "checksums.txt")
	if sums == nil {
		return "", fmt.Errorf("release %s has no checksums.txt", rel.TagName)
	}

	sumsBody, err := fetchBytes(ctx, sums.URL)
	if err != nil {
		return "", err
	}

	// Authenticity: when this build embeds a signing key, checksums.txt must carry
	// a valid minisign signature before any hash in it is trusted — a compromised
	// release origin can serve a matching checksum but cannot forge the signature.
	// Inert (skipped) when no key is configured, preserving current behaviour.
	if err := verifyChecksumsSignature(ctx, rel, sumsBody); err != nil {
		return "", err
	}

	wantSum, err := checksumFor(sumsBody, name)
	if err != nil {
		return "", err
	}

	exe, err := executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	tmp, gotSum, err := downloadToTemp(ctx, bin.URL, filepath.Dir(exe))
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tmp) }() // no-op after a successful rename

	if !strings.EqualFold(gotSum, wantSum) {
		return "", fmt.Errorf("checksum mismatch for %s: got %s, want %s", name, gotSum, wantSum)
	}
	if err := osChmod(tmp, 0o755); err != nil { // NOSONAR — executable permission is correct for a self-updating binary
		return "", err
	}
	if err := os.Rename(tmp, exe); err != nil {
		return "", fmt.Errorf("replacing %s failed: %w (try re-running with sudo, or reinstall via the installer)", exe, err)
	}
	return exe, nil
}

// fetchBytes GETs url and returns the full body. Used only for the small
// release assets (checksums.txt, the .minisig signature) — see
// maxAPIResponseBytes for why this is capped.
func fetchBytes(ctx context.Context, url string) ([]byte, error) {
	body, err := httpGet(ctx, dlClient, url)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	data, err := io.ReadAll(limitedBody(body))
	if err != nil {
		return nil, err
	}
	if limitExceeded(len(data)) {
		return nil, fmt.Errorf("response from %s exceeds maximum size (%d bytes) — refusing to read further", url, maxAPIResponseBytes)
	}
	return data, nil
}

// checksumFor returns the hex sha256 for assetName from checksums.txt content.
func checksumFor(data []byte, assetName string) (string, error) {
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == assetName {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no checksum for %s in checksums.txt", assetName)
}

// verifyChecksumsSignature enforces release authenticity when this build embeds a
// minisign public key (MinisignPublicKey). It fetches the release's
// checksums.txt.minisig and verifies it over sumsBody. When no key is configured
// it is a no-op, so unsigned/old releases keep working (checksum-only).
//
// Fail-closed: once a key IS embedded, a release that ships no signature — or a
// signature that does not verify — aborts the update rather than trusting an
// unauthenticated checksums.txt.
func verifyChecksumsSignature(ctx context.Context, rel *Release, sumsBody []byte) error {
	return verifyChecksumsSignatureKey(ctx, signingPublicKey, rel, sumsBody)
}

// verifyChecksumsSignatureKey is the key-parameterised core of
// verifyChecksumsSignature (split out so the active path is testable without
// patching the build-time MinisignPublicKey constant).
func verifyChecksumsSignatureKey(ctx context.Context, pubKey string, rel *Release, sumsBody []byte) error {
	if pubKey == "" {
		return nil // signing not configured — inert
	}
	sig := findAsset(rel.Assets, "checksums.txt.minisig")
	if sig == nil {
		return fmt.Errorf("release %s is not signed (no checksums.txt.minisig) but this build requires a verified signature", rel.TagName)
	}
	sigBody, err := fetchBytes(ctx, sig.URL)
	if err != nil {
		return fmt.Errorf("fetching release signature: %w", err)
	}
	comment, err := verifyMinisign(pubKey, sumsBody, sigBody)
	if err != nil {
		return fmt.Errorf("release signature verification failed (refusing to update): %w", err)
	}
	// Anti-rollback: a validly-signed checksums.txt+.minisig pair captured from
	// an OLDER release must not be accepted as proof THIS release is authentic
	// — the trusted comment (cryptographically bound by the global signature
	// just verified above) names the release it was actually signed for.
	if !trustedCommentNamesRelease(comment, rel.TagName) {
		return fmt.Errorf("release signature does not name %s (refusing to update — signature may be for a different release)", rel.TagName)
	}
	return nil
}

// downloadToTemp streams url into a temp file in dir, returning the path and the
// computed sha256.
func downloadToTemp(ctx context.Context, url, dir string) (string, string, error) {
	body, err := httpGet(ctx, dlClient, url)
	if err != nil {
		return "", "", err
	}
	defer body.Close()

	f, err := os.CreateTemp(dir, ".dsd-update-*")
	if err != nil {
		// Fall back to the system temp dir if the target dir isn't writable;
		// the rename will then surface a clear cross-device/permission error.
		return "", "", fmt.Errorf("cannot stage update in %s: %w", dir, err)
	}
	h := sha256.New()
	// io.LimitReader(..., maxDownloadBytes+1) rather than a bare
	// maxDownloadBytes cap so a response landing exactly at the boundary is
	// distinguishable from one that was truncated by the limit (mirrors
	// limitedBody/limitExceeded above).
	limited := io.LimitReader(body, maxDownloadBytes+1)
	written, err := io.Copy(f, io.TeeReader(limited, h))
	if err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", "", err
	}
	if written > maxDownloadBytes {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", "", fmt.Errorf("download from %s exceeds maximum size (%d bytes) — refusing to continue", url, maxDownloadBytes)
	}
	if err := closeFile(f); err != nil {
		_ = os.Remove(f.Name())
		return "", "", err
	}
	return f.Name(), hex.EncodeToString(h.Sum(nil)), nil
}

// assetURLAllowedHosts restricts release-asset downloads (checksums.txt,
// checksums.txt.minisig, and the platform binary itself) to GitHub's own
// release hosts. Every Asset.URL (browser_download_url) is taken verbatim
// from the GitHub API response; without this allowlist a compromised
// release origin could point an asset at an arbitrary internal or
// attacker-chosen host, and dsd would issue a blind outbound GET at it as
// part of `dsd update`. The checksum/minisig checks still stop a bad
// response from being installed, but do nothing to stop the request
// itself, which would otherwise be an SSRF primitive against whatever
// network the host running dsd can reach.
var assetURLAllowedHosts = map[string]bool{
	"github.com": true,
	// The CDN github.com redirects release-asset downloads to.
	"objects.githubusercontent.com":        true,
	"release-assets.githubusercontent.com": true,
}

// requireHTTPSAssetURL gates the scheme check in validateAssetURL. Always
// true in production; the test binary flips it off in TestMain so fixtures
// can point Asset.URL at a plain-http httptest.NewServer without weakening
// assetURLAllowedHosts itself (which stays a real allowlist in every case).
var requireHTTPSAssetURL = true

// validateAssetURL enforces that rawURL is an https:// GitHub release URL
// before it is ever dialed.
func validateAssetURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid asset URL %q: %w", rawURL, err)
	}
	if requireHTTPSAssetURL && u.Scheme != "https" {
		return fmt.Errorf("asset URL %q must use https, got %q", rawURL, u.Scheme)
	}
	host := u.Hostname()
	if !assetURLAllowedHosts[host] {
		return fmt.Errorf("asset URL %q has untrusted host %q (expected github.com or a githubusercontent.com release CDN)", rawURL, host)
	}
	return nil
}

func httpGet(ctx context.Context, client *http.Client, rawURL string) (io.ReadCloser, error) {
	if err := validateAssetURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s returned %d", rawURL, resp.StatusCode)
	}
	return resp.Body, nil
}
