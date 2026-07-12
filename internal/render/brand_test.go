package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
)

// resetBrand clears the CLI override + env so brand tests don't leak into each other
// or into the rest of the suite.
func resetBrand(t *testing.T) {
	t.Helper()
	SetBrand(Brand{})
	t.Setenv("DSD_BRAND_COMPANY", "")
	t.Setenv("DSD_BRAND_LOGO", "")
	t.Cleanup(func() { SetBrand(Brand{}) })
}

func TestActiveBrandOverrideAndEnvFallback(t *testing.T) {
	resetBrand(t)
	// Override wins.
	SetBrand(Brand{Company: "Flag Co", Logo: "/tmp/a.png"})
	if b := activeBrand(); b.Company != "Flag Co" || b.Logo != "/tmp/a.png" {
		t.Errorf("override not honoured: %+v", b)
	}
	// Env fills a blank field.
	SetBrand(Brand{})
	t.Setenv("DSD_BRAND_COMPANY", "Env Co")
	if b := activeBrand(); b.Company != "Env Co" {
		t.Errorf("env fallback not applied: %+v", b)
	}
	// Override takes precedence over env when both set.
	SetBrand(Brand{Company: "Flag Co"})
	if b := activeBrand(); b.Company != "Flag Co" {
		t.Errorf("override should beat env, got %q", b.Company)
	}
}

func TestLogoDataURI(t *testing.T) {
	if got := logoDataURI(""); got != "" {
		t.Errorf("empty logo must yield empty URI, got %q", got)
	}
	// Already-inline URIs pass through untouched.
	if got := logoDataURI("data:image/png;base64,AAAA"); string(got) != "data:image/png;base64,AAAA" {
		t.Errorf("data URI should pass through, got %q", got)
	}
	if got := logoDataURI("https://x/logo.png"); string(got) != "https://x/logo.png" {
		t.Errorf("http URI should pass through, got %q", got)
	}
	// A real file is embedded as a base64 data URI with the right MIME.
	dir := t.TempDir()
	png := filepath.Join(dir, "brand.png")
	if err := os.WriteFile(png, []byte("\x89PNGfake"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := string(logoDataURI(png))
	if !strings.HasPrefix(got, "data:image/png;base64,") {
		t.Errorf("file logo should embed as data:image/png, got %q", got)
	}
	// Missing file → empty (never fatal to a report).
	if got := logoDataURI(filepath.Join(dir, "nope.png")); got != "" {
		t.Errorf("missing logo must yield empty URI, got %q", got)
	}
	// Oversized file → skipped.
	big := filepath.Join(dir, "big.png")
	if err := os.WriteFile(big, make([]byte, maxLogoBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := logoDataURI(big); got != "" {
		t.Errorf("oversized logo must be skipped, got %d bytes of URI", len(got))
	}
}

func TestBrandBarHTMLEscapesAndGates(t *testing.T) {
	resetBrand(t)
	if got := brandBarHTML(); got != "" {
		t.Errorf("unbranded brand bar must be empty, got %q", got)
	}
	SetBrand(Brand{Company: `Acme <script> & Co`})
	got := brandBarHTML()
	if !strings.Contains(got, "brand-name") || strings.Contains(got, "<script>") {
		t.Errorf("company must be present and HTML-escaped, got %q", got)
	}
	if !strings.Contains(got, "&lt;script&gt;") {
		t.Errorf("expected escaped company, got %q", got)
	}
}

// TestBrandBarHTMLLogoOnly covers the branch where a logo is set but no company
// name — the <img> tag must render without the <span class="brand-name"> block.
func TestBrandBarHTMLLogoOnly(t *testing.T) {
	resetBrand(t)
	SetBrand(Brand{Logo: "data:image/png;base64,AAAA"})
	got := brandBarHTML()
	if !strings.Contains(got, `class="brand-logo"`) {
		t.Errorf("expected logo img tag, got %q", got)
	}
	if strings.Contains(got, "brand-name") {
		t.Errorf("no company set — brand-name span should be absent, got %q", got)
	}
}

// TestLogoMIME covers every extension branch, case-insensitively, plus the
// image/png default for an unrecognized/absent extension.
func TestLogoMIME(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		want string
	}{
		{"logo.jpg", "image/jpeg"},
		{"logo.JPEG", "image/jpeg"},
		{"logo.svg", "image/svg+xml"},
		{"logo.gif", "image/gif"},
		{"logo.webp", "image/webp"},
		{"logo.png", "image/png"},
		{"logo.bmp", "image/png"}, // unrecognized ext -> default
		{"logo", "image/png"},     // no ext -> default
	}
	for _, tc := range cases {
		if got := logoMIME(tc.path); got != tc.want {
			t.Errorf("logoMIME(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestBuildHTMLBrandingSwitches(t *testing.T) {
	resetBrand(t)
	snap := &baseline.Snapshot{Hostname: "h1", Timestamp: time.Now()}

	unbranded, err := buildHTML(snap, nil, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(unbranded, "DashDiag Health Report") {
		t.Error("unbranded report should carry the default DashDiag header")
	}

	SetBrand(Brand{Company: "Acme Managed Services"})
	branded, err := buildHTML(snap, nil, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(branded, "Acme Managed Services") {
		t.Error("branded report should carry the company name")
	}
	if !strings.Contains(branded, "Prepared by <b>Acme Managed Services</b>") {
		t.Error("branded footer should credit the company")
	}
	if strings.Contains(branded, "<h1>DashDiag Health Report</h1>") {
		t.Error("branded report should drop the DashDiag h1 in favour of the brand bar")
	}
	// Attribution is retained (we still get a subtle 'powered by DashDiag').
	if !strings.Contains(branded, "DashDiag") {
		t.Error("branded report should still carry a subtle DashDiag attribution")
	}
}
