//go:build linux

package cvedata

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// rhSecurityAPI is the Red Hat Security Data API base URL.
// Free, no authentication required, covers RHEL/Rocky/Fedora/CentOS.
// Var (not const) so tests can redirect it at an httptest server.
var rhSecurityAPI = "https://access.redhat.com/hydra/rest/securitydata/cve/%s.json"

// cveIDPattern is the strict MITRE CVE ID shape. EnrichFromRHAPI's only
// current caller (internal/collectors/cve_linux.go) already checks for a
// "CVE-" prefix before calling in, but that invariant lives entirely outside
// this file — this is the defense-in-depth check for any future/alternate
// caller that skips it.
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// osReleasePath is the path readOSRelease reads. Var (not a literal) so tests
// can redirect it at a fixture file instead of the real /etc/os-release.
var osReleasePath = "/etc/os-release"

// rhCVEResponse is the relevant subset of the Red Hat Security Data API response.
type rhCVEResponse struct {
	ThreatSeverity string `json:"threat_severity"`
	CVSS3          struct {
		Score  string `json:"cvss3_base_score"`
		Vector string `json:"cvss3_scoring_vector"`
	} `json:"cvss3"`
	PackageState []struct {
		ProductName string `json:"product_name"`
		FixState    string `json:"fix_state"`
		PackageName string `json:"package_name"`
		CPE         string `json:"cpe"`
	} `json:"package_state"`
}

// EnrichFromRHAPI queries the Red Hat Security Data API for a single CVE and
// populates CVSS score, threat severity, and per-product fix state onto result.
//
// Only enriches when running on a RHEL-family distro (detected via /etc/os-release).
// Fails silently — enrichment is best-effort and never blocks the primary result.
func EnrichFromRHAPI(ctx context.Context, cveID string, result *models.CVEResult) {
	// Validate the shape before it ever reaches the URL builder — the sole
	// current caller upper-cases/trims and checks a "CVE-" prefix, but that
	// check lives outside this file, so don't rely on it. An unvalidated
	// value embedding '/', '..', or other path characters must not be
	// spliced into the request path against the fixed access.redhat.com host.
	if !cveIDPattern.MatchString(cveID) {
		return
	}
	osRelease, err := readOSRelease()
	if err != nil {
		return
	}
	distro := strings.ToLower(osReleaseField(osRelease, "ID"))
	if !isRHFamily(distro) {
		return
	}

	tCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Defense-in-depth beyond the regex above: even a value that already
	// matches cveIDPattern (so this never actually alters []A-Z0-9- content
	// today) is escaped before being spliced into the URL, so a future
	// relaxation of the pattern can't silently reopen path manipulation.
	reqURL := fmt.Sprintf(rhSecurityAPI, url.QueryEscape(cveID))
	req, err := http.NewRequestWithContext(tCtx, http.MethodGet, reqURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dsd/dashdiag")

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return
	}

	var data rhCVEResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return
	}

	result.CVSS3Score = data.CVSS3.Score
	result.CVSS3Vector = data.CVSS3.Vector
	result.ThreatSev = data.ThreatSeverity

	// Find the most relevant product entry for the running distro
	rhel := detectRHELMajor()
	for _, ps := range data.PackageState {
		nameLower := strings.ToLower(ps.ProductName)
		if strings.Contains(nameLower, rhel) ||
			strings.Contains(nameLower, distro) ||
			strings.Contains(ps.CPE, ":"+rhel) {
			result.FixState = ps.FixState
			result.AffectedPkg = ps.PackageName
			break
		}
	}
	// Fallback: first entry if nothing matched
	if result.FixState == "" && len(data.PackageState) > 0 {
		result.FixState = data.PackageState[0].FixState
		result.AffectedPkg = data.PackageState[0].PackageName
	}

	// If RH API says "Not affected" and package manager is uncertain, clarify status
	if result.FixState == "Not affected" && result.Status == models.CVENotAffected {
		result.StatusReason = "Red Hat confirmed: not affected on this product"
	}
}

// isRHFamily returns true for RHEL, Rocky, AlmaLinux, CentOS, Fedora.
func isRHFamily(distro string) bool {
	for _, kw := range []string{"rhel", "red hat", "rocky", "alma", "centos", "fedora"} {
		if strings.Contains(distro, kw) {
			return true
		}
	}
	return false
}

// detectRHELMajor returns "enterprise_linux:10", "enterprise_linux:9", etc.
// Used to match CPE strings in the RH API response.
func detectRHELMajor() string {
	data, err := readOSRelease()
	if err != nil {
		return "enterprise_linux"
	}
	ver := osReleaseField(data, "VERSION_ID")
	major := strings.SplitN(ver, ".", 2)[0]
	if major == "" {
		return "enterprise_linux"
	}
	return "enterprise_linux:" + major
}

// readOSRelease reads /etc/os-release (or osReleasePath, when a test
// redirects it) and returns its content.
func readOSRelease() (string, error) {
	data, err := os.ReadFile(osReleasePath) // #nosec G304
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// osReleaseField extracts a field value from /etc/os-release content.
// e.g. osReleaseField(data, "ID") → "rhel"
func osReleaseField(content, key string) string {
	prefix := key + "="
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.Trim(strings.TrimPrefix(line, prefix), "\"")
		}
	}
	return ""
}
