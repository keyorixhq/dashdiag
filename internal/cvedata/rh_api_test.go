//go:build linux

package cvedata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ── isRHFamily (pure) ─────────────────────────────────────────────────────

func TestIsRHFamily(t *testing.T) {
	t.Parallel()
	cases := []struct {
		distro string
		want   bool
	}{
		{"rhel", true},
		{"red hat enterprise linux", true},
		{"rocky", true},
		{"almalinux", true},
		{"centos", true},
		{"fedora", true},
		{"ubuntu", false},
		{"debian", false},
		{"opensuse-leap", false},
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.distro, func(t *testing.T) {
			t.Parallel()
			if got := isRHFamily(c.distro); got != c.want {
				t.Errorf("isRHFamily(%q) = %v, want %v", c.distro, got, c.want)
			}
		})
	}
}

// ── osReleaseField (pure) ────────────────────────────────────────────────

func TestOSReleaseField(t *testing.T) {
	t.Parallel()
	content := "NAME=\"Red Hat Enterprise Linux\"\nID=\"rhel\"\nVERSION_ID=\"9.4\"\n"
	cases := []struct {
		key  string
		want string
	}{
		{"ID", "rhel"},
		{"VERSION_ID", "9.4"},
		{"NAME", "Red Hat Enterprise Linux"},
		{"NOPE", ""},
	}
	for _, c := range cases {
		if got := osReleaseField(content, c.key); got != c.want {
			t.Errorf("osReleaseField(%q) = %q, want %q", c.key, got, c.want)
		}
	}
}

// ── readOSRelease / detectRHELMajor (via the osReleasePath seam) ───────────
//
// These tests redirect the package-level osReleasePath var at a fixture file
// instead of reading /etc/os-release, so they must not run t.Parallel()
// alongside each other (shared mutable package state) — each resets the var
// via t.Cleanup before returning.

func withOSRelease(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := osReleasePath
	osReleasePath = path
	t.Cleanup(func() { osReleasePath = prev })
}

func TestReadOSRelease(t *testing.T) {
	withOSRelease(t, "ID=rhel\nVERSION_ID=\"9.4\"\n")
	got, err := readOSRelease()
	if err != nil {
		t.Fatalf("readOSRelease: %v", err)
	}
	if osReleaseField(got, "ID") != "rhel" {
		t.Errorf("readOSRelease content ID = %q", osReleaseField(got, "ID"))
	}
}

func TestReadOSRelease_MissingFile(t *testing.T) {
	prev := osReleasePath
	osReleasePath = filepath.Join(t.TempDir(), "nope")
	t.Cleanup(func() { osReleasePath = prev })
	if _, err := readOSRelease(); err == nil {
		t.Error("expected error when os-release path doesn't exist")
	}
}

func TestDetectRHELMajor(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"rhel9", "ID=rhel\nVERSION_ID=\"9.4\"\n", "enterprise_linux:9"},
		{"rocky10", "ID=rocky\nVERSION_ID=\"10\"\n", "enterprise_linux:10"},
		{"no version_id", "ID=rhel\n", "enterprise_linux"},
	}
	for _, c := range cases {
		withOSRelease(t, c.content)
		if got := detectRHELMajor(); got != c.want {
			t.Errorf("%s: detectRHELMajor() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDetectRHELMajor_ReadError(t *testing.T) {
	prev := osReleasePath
	osReleasePath = filepath.Join(t.TempDir(), "nope")
	t.Cleanup(func() { osReleasePath = prev })
	if got := detectRHELMajor(); got != "enterprise_linux" {
		t.Errorf("detectRHELMajor() with unreadable os-release = %q, want fallback \"enterprise_linux\"", got)
	}
}

// ── EnrichFromRHAPI (httptest server + both seams) ──────────────────────────

// TestEnrichFromRHAPI_ReadOSReleaseErrorIsSilent exercises the earliest
// return in EnrichFromRHAPI: when /etc/os-release (redirected via
// osReleasePath) can't be read at all, enrichment must silently no-op rather
// than propagate the error (best-effort by design — see the function doc).
func TestEnrichFromRHAPI_ReadOSReleaseErrorIsSilent(t *testing.T) {
	prev := osReleasePath
	osReleasePath = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { osReleasePath = prev })

	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()
	prevAPI := rhSecurityAPI
	rhSecurityAPI = srv.URL + "/%s.json"
	t.Cleanup(func() { rhSecurityAPI = prevAPI })

	result := &models.CVEResult{}
	EnrichFromRHAPI(context.Background(), "CVE-2024-0006", result)
	if called {
		t.Error("EnrichFromRHAPI must not call the network when os-release can't be read")
	}
	if result.CVSS3Score != "" {
		t.Errorf("result should be untouched, got %+v", result)
	}
}

// TestEnrichFromRHAPI_MalformedURLIsSilent exercises the
// http.NewRequestWithContext error branch: a CVE ID containing control
// characters (here embedded via a rhSecurityAPI template with no %s, so the
// literal cveID lands in the URL) produces a URL http.NewRequestWithContext
// rejects, and EnrichFromRHAPI must swallow the error rather than panic.
func TestEnrichFromRHAPI_MalformedURLIsSilent(t *testing.T) {
	withOSRelease(t, "ID=rhel\nVERSION_ID=\"9.4\"\n")
	prevAPI := rhSecurityAPI
	// A control character (raw newline) in the URL path makes
	// http.NewRequestWithContext return "net/url: invalid control character
	// in URL" — deterministic without needing a live listener.
	rhSecurityAPI = "http://127.0.0.1:0/%s\n.json"
	t.Cleanup(func() { rhSecurityAPI = prevAPI })

	result := &models.CVEResult{}
	EnrichFromRHAPI(context.Background(), "CVE-2024-0007", result) // must not panic
	if result.CVSS3Score != "" {
		t.Errorf("expected untouched result on malformed request URL, got %+v", result)
	}
}

// TestEnrichFromRHAPI_BodyReadErrorIsSilent exercises the io.ReadAll error
// branch: the server advertises a Content-Length larger than what it
// actually sends and then closes the connection, so reading the body fails
// partway through. EnrichFromRHAPI must swallow that error too.
func TestEnrichFromRHAPI_BodyReadErrorIsSilent(t *testing.T) {
	withOSRelease(t, "ID=rhel\nVERSION_ID=\"9.4\"\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{")) // far short of the advertised length
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close() // force a truncated read on the client side
			}
		}
	}))
	defer srv.Close()
	prevAPI := rhSecurityAPI
	rhSecurityAPI = srv.URL + "/%s.json"
	t.Cleanup(func() { rhSecurityAPI = prevAPI })

	result := &models.CVEResult{}
	EnrichFromRHAPI(context.Background(), "CVE-2024-0008", result) // must not panic
	if result.CVSS3Score != "" {
		t.Errorf("expected untouched result on truncated body read, got %+v", result)
	}
}

func TestEnrichFromRHAPI_NonRHFamilySkipsNetworkCall(t *testing.T) {
	withOSRelease(t, "ID=ubuntu\nVERSION_ID=\"24.04\"\n")
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()
	prevAPI := rhSecurityAPI
	rhSecurityAPI = srv.URL + "/%s.json"
	t.Cleanup(func() { rhSecurityAPI = prevAPI })

	result := &models.CVEResult{}
	EnrichFromRHAPI(context.Background(), "CVE-2024-0001", result)
	if called {
		t.Error("EnrichFromRHAPI must not call the network on a non-RH-family distro")
	}
	if result.CVSS3Score != "" {
		t.Errorf("result should be untouched, got %+v", result)
	}
}

// TestCVEIDPattern is a direct table-driven boundary test of the strict CVE
// ID shape guarding Finding internal-cvedata-02-02: EnrichFromRHAPI built its
// outbound request URL with fmt.Sprintf(rhSecurityAPI, cveID) with no
// validation of cveID within this file, relying entirely on the sole current
// caller to have enforced a "CVE-" prefix — no defense-in-depth against a
// value embedding '/', '..', or other path characters.
func TestCVEIDPattern(t *testing.T) {
	t.Parallel()
	cases := []struct {
		id   string
		want bool
	}{
		{"CVE-2024-0001", true},
		{"CVE-2024-12345", true},
		{"CVE-1999-9999", true},
		{"", false},
		{"cve-2024-0001", false},        // lowercase
		{"CVE-2024-1", false},           // fewer than 4 digits in the sequence number
		{"CVE-24-0001", false},          // fewer than 4 digits in the year
		{"CVE-2024-0001/../etc", false}, // path traversal attempt
		{"CVE-2024-0001&x=1", false},    // query-string injection attempt
		{"not-a-cve", false},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			t.Parallel()
			if got := cveIDPattern.MatchString(c.id); got != c.want {
				t.Errorf("cveIDPattern.MatchString(%q) = %v, want %v", c.id, got, c.want)
			}
		})
	}
}

// TestEnrichFromRHAPI_InvalidCVEIDSkipsNetworkCall guards the defense-in-
// depth check itself: a cveID that doesn't match the strict CVE- shape must
// never reach the URL builder or make a network call, even on an otherwise
// RH-family host.
func TestEnrichFromRHAPI_InvalidCVEIDSkipsNetworkCall(t *testing.T) {
	withOSRelease(t, "ID=rhel\nVERSION_ID=\"9.4\"\n")
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()
	prevAPI := rhSecurityAPI
	rhSecurityAPI = srv.URL + "/%s.json"
	t.Cleanup(func() { rhSecurityAPI = prevAPI })

	for _, bad := range []string{"", "not-a-cve", "CVE-2024-0001/../etc/passwd", "CVE-2024-0001&x=1"} {
		result := &models.CVEResult{}
		EnrichFromRHAPI(context.Background(), bad, result)
		if called {
			t.Errorf("EnrichFromRHAPI(%q) must not call the network for an invalid CVE ID", bad)
		}
		if result.CVSS3Score != "" {
			t.Errorf("EnrichFromRHAPI(%q): result should be untouched, got %+v", bad, result)
		}
	}
}

func TestEnrichFromRHAPI_PopulatesFromResponse(t *testing.T) {
	withOSRelease(t, "ID=rhel\nVERSION_ID=\"9.4\"\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"threat_severity": "Important",
			"cvss3": {"cvss3_base_score": "8.1", "cvss3_scoring_vector": "CVSS:3.1/AV:N"},
			"package_state": [
				{"product_name": "Red Hat Enterprise Linux 9", "fix_state": "Affected", "package_name": "openssl", "cpe": "cpe:/o:redhat:enterprise_linux:9"}
			]
		}`))
	}))
	defer srv.Close()
	prevAPI := rhSecurityAPI
	rhSecurityAPI = srv.URL + "/%s.json"
	t.Cleanup(func() { rhSecurityAPI = prevAPI })

	result := &models.CVEResult{}
	EnrichFromRHAPI(context.Background(), "CVE-2024-0001", result)
	if result.CVSS3Score != "8.1" || result.ThreatSev != "Important" {
		t.Errorf("result = %+v, want CVSS3Score=8.1 ThreatSev=Important", result)
	}
	if result.FixState != "Affected" || result.AffectedPkg != "openssl" {
		t.Errorf("result = %+v, want FixState=Affected AffectedPkg=openssl (matched via enterprise_linux:9)", result)
	}
}

func TestEnrichFromRHAPI_FallsBackToFirstPackageStateEntry(t *testing.T) {
	withOSRelease(t, "ID=rhel\nVERSION_ID=\"9.4\"\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"package_state": [
				{"product_name": "Some Unrelated Product", "fix_state": "Will not fix", "package_name": "foo", "cpe": "cpe:/o:other:thing:1"}
			]
		}`))
	}))
	defer srv.Close()
	prevAPI := rhSecurityAPI
	rhSecurityAPI = srv.URL + "/%s.json"
	t.Cleanup(func() { rhSecurityAPI = prevAPI })

	result := &models.CVEResult{}
	EnrichFromRHAPI(context.Background(), "CVE-2024-0002", result)
	if result.FixState != "Will not fix" || result.AffectedPkg != "foo" {
		t.Errorf("result = %+v, want the fallback first entry", result)
	}
}

func TestEnrichFromRHAPI_NotAffectedClarifiesReason(t *testing.T) {
	withOSRelease(t, "ID=rhel\nVERSION_ID=\"9.4\"\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"package_state": [
				{"product_name": "Red Hat Enterprise Linux 9", "fix_state": "Not affected", "package_name": "openssl", "cpe": "cpe:/o:redhat:enterprise_linux:9"}
			]
		}`))
	}))
	defer srv.Close()
	prevAPI := rhSecurityAPI
	rhSecurityAPI = srv.URL + "/%s.json"
	t.Cleanup(func() { rhSecurityAPI = prevAPI })

	result := &models.CVEResult{Status: models.CVENotAffected}
	EnrichFromRHAPI(context.Background(), "CVE-2024-0003", result)
	if result.StatusReason == "" {
		t.Error("expected StatusReason to be set when RH API confirms Not affected and status already agrees")
	}
}

func TestEnrichFromRHAPI_HTTPErrorIsSilent(t *testing.T) {
	withOSRelease(t, "ID=rhel\nVERSION_ID=\"9.4\"\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	prevAPI := rhSecurityAPI
	rhSecurityAPI = srv.URL + "/%s.json"
	t.Cleanup(func() { rhSecurityAPI = prevAPI })

	result := &models.CVEResult{}
	EnrichFromRHAPI(context.Background(), "CVE-2024-0004", result) // must not panic or error out loud
	if result.CVSS3Score != "" {
		t.Errorf("expected untouched result on HTTP error, got %+v", result)
	}
}

func TestEnrichFromRHAPI_MalformedJSONIsSilent(t *testing.T) {
	withOSRelease(t, "ID=rhel\nVERSION_ID=\"9.4\"\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer srv.Close()
	prevAPI := rhSecurityAPI
	rhSecurityAPI = srv.URL + "/%s.json"
	t.Cleanup(func() { rhSecurityAPI = prevAPI })

	result := &models.CVEResult{}
	EnrichFromRHAPI(context.Background(), "CVE-2024-0005", result)
	if result.CVSS3Score != "" {
		t.Errorf("expected untouched result on malformed JSON, got %+v", result)
	}
}
