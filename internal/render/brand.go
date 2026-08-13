package render

import (
	"encoding/base64"
	"fmt"
	"html"
	"html/template"
	"net/url"
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
// base64-embedded; an already-inline data:/https: URI passes through. Returns ("", nil) if
// the logo is absent; returns ("", error) for rejected inputs (SVG, non-image data: URIs,
// http:// URLs, unreadable or oversized files). A missing logo is never fatal to a report —
// callers should log the error but continue rendering. Typed template.URL so html/template
// does not strip the data: URI.
func logoDataURI(logo string) (template.URL, error) {
	logo = strings.TrimSpace(logo)
	if logo == "" {
		return "", nil
	}
	// Reject plain http:// — breaks the self-contained single-file invariant and
	// leaks report opens to the logo host. Only https:// is allowed as a URL.
	if strings.HasPrefix(logo, "http://") {
		return "", fmt.Errorf("http:// logo URLs are not supported; use https:// or a local file path")
	}
	if strings.HasPrefix(logo, "https://") {
		if !isSafeAttrURI(logo) {
			return "", fmt.Errorf("logo URL contains characters unsafe for an HTML attribute")
		}
		return template.URL(logo), nil //nolint:gosec // operator-supplied HTTPS URI, self-contained report
	}
	// Validate data: URIs — only image/* MIME types are safe to embed.
	// data:text/html or data:application/... can contain executable content.
	if strings.HasPrefix(logo, "data:") {
		if !strings.HasPrefix(logo, "data:image/") {
			return "", fmt.Errorf("data: logo URI must use an image/* MIME type")
		}
		if !isSafeAttrURI(logo) {
			return "", fmt.Errorf("logo data: URI contains characters unsafe for an HTML attribute")
		}
		return template.URL(logo), nil //nolint:gosec // validated image/* data URI
	}
	// File path: clean the path to prevent directory traversal, then read and embed.
	logo = filepath.Clean(logo)
	mime := logoMIME(logo)
	// Only allow raster image types — SVG can contain executable JavaScript via
	// <script> elements and event handlers, which execute when the report is opened.
	switch mime {
	case "image/png", "image/jpeg", "image/gif", "image/webp", "image/x-icon":
		// allowed
	default:
		return "", fmt.Errorf("unsupported logo format %q: only PNG, JPEG, GIF, WEBP, ICO allowed (SVG rejected — can contain scripts)", filepath.Ext(logo))
	}
	data, err := os.ReadFile(logo) //nolint:gosec // operator-supplied brand asset path, cleaned above
	if err != nil {
		return "", fmt.Errorf("reading logo file: %w", err)
	}
	if len(data) == 0 || len(data) > maxLogoBytes {
		return "", fmt.Errorf("logo file %q is empty or exceeds %d bytes", logo, maxLogoBytes)
	}
	return template.URL(fmt.Sprintf("data:%s;base64,%s", mime, base64.StdEncoding.EncodeToString(data))), nil //nolint:gosec // self-generated data URI
}

// isSafeAttrURI reports whether s is safe to embed verbatim into an HTML
// src="..." attribute. logoDataURI returns https:// and data: logo URIs as
// template.URL, which html/template treats as pre-vetted and emits WITHOUT
// any escaping (per html/template's docs: "included verbatim in the template
// output") — so an operator-supplied (or automation-fed) URL/URI containing
// a quote, angle bracket, or backtick could break out of the attribute and
// inject arbitrary HTML/JS into the report. A well-formed https:// URL or
// base64 data: URI never legitimately needs any of these characters.
func isSafeAttrURI(s string) bool {
	return !strings.ContainsAny(s, "\"'<>`") && !strings.ContainsFunc(s, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	})
}

func logoMIME(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".ico":
		return "image/x-icon"
	case ".svg":
		return "image/svg+xml" // returned so the caller's switch can produce a useful error
	default:
		return "image/png"
	}
}

// brandBarHTML renders the header brand bar (logo + company name) for reports built by
// manual string assembly (the guest two-block report). Returns "" when unbranded.
// Company is HTML-escaped; the logo URI is self-generated/operator-supplied.
// Logo errors (SVG, non-image data: URIs, http:// URLs) are logged to stderr and the
// logo is omitted — a bad logo never prevents the report from being generated.
func brandBarHTML() string {
	b := activeBrand()
	if b.Company == "" && b.Logo == "" {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<div class="brandbar">`)
	if b.Logo != "" {
		uri, err := logoDataURI(b.Logo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dsd: logo rejected: %v\n", err)
		} else if uri != "" {
			// referrerpolicy strips the report's origin from the request an
			// https:// logo triggers; loading="lazy" avoids fetching it purely
			// because a report renderer scrolled past it. Neither stops the load
			// itself — that's inherent to an operator choosing a remote logo URL
			// over an embedded file/data: URI — so an https logo also gets a
			// visible disclosure (below) telling whoever opens the report that
			// doing so contacts a third-party host, which a self-contained
			// file/data: logo never does.
			fmt.Fprintf(&sb, `<img class="brand-logo" src="%s" alt="%s" referrerpolicy="no-referrer" loading="lazy">`,
				uri, html.EscapeString(b.Company))
			if note := externalLogoDisclosure(b.Logo); note != "" {
				sb.WriteString(note)
			}
		}
	}
	if b.Company != "" {
		fmt.Fprintf(&sb, `<span class="brand-name">%s</span>`, html.EscapeString(b.Company))
	}
	sb.WriteString("</div>\n")
	return sb.String()
}

// externalLogoDisclosure returns a small visible notice when logo is an
// https:// URL rather than a self-contained file/data: URI, so a report
// recipient can see — without inspecting the HTML source — that opening the
// report causes their browser to load an image from a third-party host
// (rawLogoHost, revealing the recipient's IP/user-agent/open-time to
// whoever controls that host). Returns "" for file/data: logos, which never
// make an outbound request when the report is opened.
func externalLogoDisclosure(logo string) string {
	logo = strings.TrimSpace(logo)
	if !strings.HasPrefix(logo, "https://") {
		return ""
	}
	host := logo
	if u, err := url.Parse(logo); err == nil && u.Host != "" {
		host = u.Host
	}
	return fmt.Sprintf(
		`<small class="brand-logo-disclosure" title="Opening this report loads an image from %s.">`+
			`&#9432; logo loaded from %s</small>`,
		html.EscapeString(host), html.EscapeString(host))
}
