package render

import (
	"encoding/base64"
	"fmt"
	"html"
	"html/template"
	"os"
	"path/filepath"
	"strings"
)

// Brand carries white-label options for the HTML reports: the company name that
// appears in the header/footer and an optional logo. It lets an MSP or consultancy
// hand a client a report under its OWN brand while dsd keeps a small "powered by"
// attribution. Set via `--brand`/`--logo` flags or the DSD_BRAND_COMPANY /
// DSD_BRAND_LOGO env vars (env is convenient for an MSP that brands every run).
type Brand struct {
	Company string // e.g. "Acme Managed Services"
	Logo    string // file path, or a data:/https: URI, embedded self-contained
}

// brandOverride is the CLI/programmatic brand; env vars fill any blank field.
var brandOverride Brand

// SetBrand sets the active report brand (from --brand/--logo flags).
func SetBrand(b Brand) { brandOverride = b }

// activeBrand merges the CLI override with the environment fallback, so a report is
// branded whether the caller wired flags or just exported DSD_BRAND_* in its shell.
func activeBrand() Brand {
	b := brandOverride
	if b.Company == "" {
		b.Company = strings.TrimSpace(os.Getenv("DSD_BRAND_COMPANY"))
	}
	if b.Logo == "" {
		b.Logo = strings.TrimSpace(os.Getenv("DSD_BRAND_LOGO"))
	}
	return b
}

// maxLogoBytes caps an embedded logo so a report stays a small, emailable file. A
// logo larger than this is almost certainly a mistake (a photo, not a mark) — skip it.
const maxLogoBytes = 512 * 1024

// logoDataURI turns a logo reference into a self-contained data: URI (so the report
// remains a single file that survives email and offline viewing). A path is read and
// base64-embedded; an already-inline data:/http(s): URI passes through. Returns "" if
// the logo is absent, unreadable, or too large — a missing logo is never fatal to a
// report. Typed template.URL so html/template does not strip the data: URI.
func logoDataURI(logo string) template.URL {
	logo = strings.TrimSpace(logo)
	if logo == "" {
		return ""
	}
	if strings.HasPrefix(logo, "data:") || strings.HasPrefix(logo, "http://") || strings.HasPrefix(logo, "https://") {
		return template.URL(logo) //nolint:gosec // caller-supplied brand URI, self-contained report
	}
	data, err := os.ReadFile(logo) //nolint:gosec // operator-supplied brand asset path
	if err != nil || len(data) == 0 || len(data) > maxLogoBytes {
		return ""
	}
	mime := logoMIME(logo)
	return template.URL(fmt.Sprintf("data:%s;base64,%s", mime, base64.StdEncoding.EncodeToString(data))) //nolint:gosec // self-generated data URI
}

func logoMIME(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".svg":
		return "image/svg+xml"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	default:
		return "image/png"
	}
}

// brandBarHTML renders the header brand bar (logo + company name) for reports built by
// manual string assembly (the guest two-block report). Returns "" when unbranded.
// Company is HTML-escaped; the logo URI is self-generated/operator-supplied.
func brandBarHTML() string {
	b := activeBrand()
	if b.Company == "" && b.Logo == "" {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<div class="brandbar">`)
	if uri := logoDataURI(b.Logo); uri != "" {
		fmt.Fprintf(&sb, `<img class="brand-logo" src="%s" alt="%s">`, uri, html.EscapeString(b.Company))
	}
	if b.Company != "" {
		fmt.Fprintf(&sb, `<span class="brand-name">%s</span>`, html.EscapeString(b.Company))
	}
	sb.WriteString("</div>\n")
	return sb.String()
}
