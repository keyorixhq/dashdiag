// Package selfupdate implements `dsd update` — query the GitHub releases API,
// download the platform binary, verify its sha256 against the release's
// checksums.txt, and atomically replace the running binary. It also backs the
// passive "newer version available" nudge via a TTL-cached check.
//
// Safety: the nudge never blocks the hot path beyond a short timeout, is gated
// to interactive runs, is disabled by DSD_NO_UPDATE_CHECK, and never nags dev
// builds. The self-replace is atomic (download to a temp file in the target dir,
// verify, then rename over the running binary).
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repo is the GitHub owner/name the updater talks to.
const Repo = "keyorixhq/dashdiag"

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
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
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
	for i := 0; i < 3; i++ {
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
		if i > 2 {
			break
		}
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
	if err := os.Chmod(tmp, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, exe); err != nil {
		return "", fmt.Errorf("replacing %s failed: %w (try re-running with sudo, or reinstall via the installer)", exe, err)
	}
	return exe, nil
}

// fetchBytes GETs url and returns the full body.
func fetchBytes(ctx context.Context, url string) ([]byte, error) {
	body, err := httpGet(ctx, dlClient, url)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(body)
}

// checksumFor returns the hex sha256 for assetName from checksums.txt content.
func checksumFor(data []byte, assetName string) (string, error) {
	for _, line := range strings.Split(string(data), "\n") {
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
	return verifyChecksumsSignatureKey(ctx, MinisignPublicKey, rel, sumsBody)
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
	if err := verifyMinisign(pubKey, sumsBody, sigBody); err != nil {
		return fmt.Errorf("release signature verification failed (refusing to update): %w", err)
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
	if _, err := io.Copy(f, io.TeeReader(body, h)); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", "", err
	}
	return f.Name(), hex.EncodeToString(h.Sum(nil)), nil
}

func httpGet(ctx context.Context, client *http.Client, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s returned %d", url, resp.StatusCode)
	}
	return resp.Body, nil
}
