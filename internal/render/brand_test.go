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
	t.Parallel()
	// Empty logo → empty URI, no error.
	got, err := logoDataURI("")
	if got != "" || err != nil {
		t.Errorf("empty logo must yield (\"\", nil), got (%q, %v)", got, err)
	}
	// image/* data URIs pass through untouched.
	got, err = logoDataURI("data:image/png;base64,AAAA")
	if string(got) != "data:image/png;base64,AAAA" || err != nil {
		t.Errorf("data:image/ URI should pass through, got (%q, %v)", got, err)
	}
	// Non-image data: URIs are rejected.
	_, err = logoDataURI("data:text/html,<script>alert(1)</script>")
	if err == nil {
		t.Error("data:text/html URI must be rejected")
	}
	// https:// URIs pass through.
	got, err = logoDataURI("https://x/logo.png")
	if string(got) != "https://x/logo.png" || err != nil {
		t.Errorf("https URI should pass through, got (%q, %v)", got, err)
	}
	// http:// URIs are rejected.
	_, err = logoDataURI("http://x/logo.png")
	if err == nil {
		t.Error("http:// URI must be rejected")
	}
	// An oversized https:// URL is rejected — same maxLogoBytes cap as the
	// data: URI and file-path branches, applied to the URL string itself.
	hugeURL := "https://x/" + strings.Repeat("a", maxLogoBytes)
	_, err = logoDataURI(hugeURL)
	if err == nil {
		t.Error("oversized https:// logo URL must be rejected")
	}
	// An https:// URL containing a quote must be rejected — logoDataURI returns
	// template.URL, which html/template emits verbatim with NO escaping, so an
	// unquoted-attribute-breakout character would inject arbitrary HTML/JS into
	// the report.
	_, err = logoDataURI(`https://evil.example/x.png" onerror="alert(1)`)
	if err == nil {
		t.Error("https:// URL containing a quote must be rejected (HTML attribute breakout)")
	}
	// Same risk for a data: URI carrying a quote in its (unvalidated) MIME params.
	_, err = logoDataURI(`data:image/png;base64,AAAA" onerror="alert(1)`)
	if err == nil {
		t.Error("data: URI containing a quote must be rejected (HTML attribute breakout)")
	}
	// SVG files are rejected.
	dir := t.TempDir()
	svg := filepath.Join(dir, "logo.svg")
	if err2 := os.WriteFile(svg, []byte("<svg><script>alert(1)</script></svg>"), 0o600); err2 != nil {
		t.Fatal(err2)
	}
	_, err = logoDataURI(svg)
	if err == nil {
		t.Error("SVG logo must be rejected")
	}
	// A real PNG file is embedded as a base64 data URI with the right MIME.
	png := filepath.Join(dir, "brand.png")
	if err2 := os.WriteFile(png, []byte("\x89PNGfake"), 0o600); err2 != nil {
		t.Fatal(err2)
	}
	got, err = logoDataURI(png)
	if err != nil {
		t.Fatalf("valid PNG logo returned error: %v", err)
	}
	if !strings.HasPrefix(string(got), "data:image/png;base64,") {
		t.Errorf("file logo should embed as data:image/png, got %q", got)
	}
	// Missing file → error.
	_, err = logoDataURI(filepath.Join(dir, "nope.png"))
	if err == nil {
		t.Error("missing logo file must return an error")
	}
	// Oversized file → error.
	big := filepath.Join(dir, "big.png")
	if err2 := os.WriteFile(big, make([]byte, maxLogoBytes+1), 0o600); err2 != nil {
		t.Fatal(err2)
	}
	_, err = logoDataURI(big)
	if err == nil {
		t.Error("oversized logo must return an error")
	}
}

// TestLogoDataURI_RejectsOversizedDataURI covers internal-render-01-04: the
// file-path branch above size-checks before embedding, but a data: URI is
// embedded verbatim with no read step to check first — it must be capped
// the same way, or a caller-supplied (env var / --logo) data: URI could
// bloat every report by an arbitrary amount.
func TestLogoDataURI_RejectsOversizedDataURI(t *testing.T) {
	t.Parallel()
	huge := "data:image/png;base64," + strings.Repeat("A", maxLogoBytes+1)
	_, err := logoDataURI(huge)
	if err == nil {
		t.Error("oversized data: logo URI must return an error, not be embedded verbatim")
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

// TestBrandBarHTMLExternalLogoDiscloses is a regression guard for
// internal-render-01-06: an https:// logo becomes a silent open-tracking
// beacon — the report itself carried no indication that opening it makes the
// viewer's browser load an image from the operator-chosen third-party host,
// disclosing that recipient's IP/user-agent/open-time. The <img> tag must
// carry referrerpolicy="no-referrer", and the rendered brand bar must include
// a human-visible disclosure naming the host, not just an HTML comment only
// visible via "view source".
func TestBrandBarHTMLExternalLogoDiscloses(t *testing.T) {
	resetBrand(t)
	SetBrand(Brand{Logo: "https://tracker.example.com/logo.png"})
	got := brandBarHTML()
	if !strings.Contains(got, `referrerpolicy="no-referrer"`) {
		t.Errorf("expected the logo <img> to carry referrerpolicy=\"no-referrer\", got %q", got)
	}
	if !strings.Contains(got, "brand-logo-disclosure") {
		t.Errorf("expected a visible external-logo disclosure element, got %q", got)
	}
	if !strings.Contains(got, "tracker.example.com") {
		t.Errorf("expected the disclosure to name the logo host, got %q", got)
	}
}

// TestBrandBarHTMLLocalLogoNoDisclosure confirms a self-contained data:/file
// logo — which never triggers a request when the report is opened — gets no
// disclosure note.
func TestBrandBarHTMLLocalLogoNoDisclosure(t *testing.T) {
	resetBrand(t)
	SetBrand(Brand{Logo: "data:image/png;base64,AAAA"})
	got := brandBarHTML()
	if strings.Contains(got, "brand-logo-disclosure") {
		t.Errorf("a self-contained data: logo must not get an external-disclosure note, got %q", got)
	}
}

// TestBrandBarHTMLRejectedLogoOmitted covers brandBarHTML's logoDataURI
// error branch: a rejected logo (here, a plain http:// URL) must not
// prevent the report from rendering — it's logged to stderr and simply
// omitted, no <img> tag at all.
func TestBrandBarHTMLRejectedLogoOmitted(t *testing.T) {
	resetBrand(t)
	SetBrand(Brand{Company: "Acme Co", Logo: "http://insecure.example/logo.png"})
	got := brandBarHTML()
	if strings.Contains(got, `class="brand-logo"`) {
		t.Errorf("a rejected logo must not produce an <img> tag, got %q", got)
	}
	if !strings.Contains(got, "brand-name") {
		t.Errorf("company should still render even though the logo was rejected, got %q", got)
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
		{"logo.svg", "image/svg+xml"}, // returned so caller's switch produces a useful error
		{"logo.gif", "image/gif"},
		{"logo.webp", "image/webp"},
		{"logo.ico", "image/x-icon"},
		{"logo.ICO", "image/x-icon"},
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
