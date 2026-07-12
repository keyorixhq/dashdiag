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
