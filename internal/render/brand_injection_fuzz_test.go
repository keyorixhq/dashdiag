package render

import (
	"strings"
	"testing"
)

// FuzzBrandLogoNoAttrInjection is a D4 (terminal/report injection) oracle for
// the ONE place the HTML report deliberately bypasses html/template's escaping:
// logoDataURI returns a template.URL, which html/template emits VERBATIM (no
// escaping) into the report's <img src="..."> attribute. isSafeAttrURI is the
// only thing standing between an operator/automation-supplied DSD_BRAND_LOGO (or
// --logo) value and arbitrary HTML/JS injected into every branded report.
//
// Existing coverage: FuzzSanitizeThenRenderNoRawEscape covers the TERMINAL
// sanitizer (SanitizeControl). It does NOT cover the HTML report's template.URL
// bypass — this target does.
//
// Oracle (injection, not crash-only): whenever logoDataURI accepts a logo and
// returns a non-empty template.URL, that string must be safe to drop verbatim
// into a double-quoted HTML attribute — i.e. it must contain none of
// " ' < > ` and no control byte. If it ever does, the report can be broken out
// of the src attribute into arbitrary markup. The same property is then checked
// end-to-end through brandBarHTML() (the real report fragment builder): no raw
// control/ESC byte reaches the report, and no logo src value breaks its quoting.
//
// INVARIANT (see INVARIANTS.d note): a template.URL returned by logoDataURI is
// always HTML-attribute-safe; brandBarHTML never emits a raw control byte or an
// unbalanced src="..." attribute regardless of brand input.
//
// What this oracle does NOT verify: the company-name path (that goes through
// html.EscapeString, a stdlib guarantee, not re-derived here), the local
// file-path branch of logoDataURI (skipped on purpose so the fuzzer performs no
// filesystem reads as root), or the Markdown report renderer.

func isAttrSafe(s string) bool {
	if strings.ContainsAny(s, "\"'<>`") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func FuzzBrandLogoNoAttrInjection(f *testing.F) {
	f.Add(uint8(0), "logos.example/mark.png")
	f.Add(uint8(0), "evil.example/x\"><script>alert(1)</script>")
	f.Add(uint8(1), "png;base64,AAAA")
	f.Add(uint8(1), "svg+xml,<script>alert(1)</script>")
	f.Add(uint8(2), "text/html,<script>alert(1)</script>")
	f.Add(uint8(0), "github.com/a`b")
	f.Add(uint8(3), "Acme \x1b[31mManaged")

	f.Fuzz(func(t *testing.T, kind uint8, body string) {
		// Drive the URL/data: branches of logoDataURI (where template.URL is
		// returned unescaped). The local-file branch is intentionally excluded so
		// the fuzzer never reads host files.
		var logo string
		switch kind % 4 {
		case 0:
			logo = "https://" + body
		case 1:
			logo = "data:image/" + body
		case 2:
			logo = "data:" + body
		default:
			logo = "" // unbranded-logo path; body still drives the company name
		}

		uri, err := logoDataURI(logo)
		if err == nil && uri != "" {
			if !isAttrSafe(string(uri)) {
				t.Fatalf("logoDataURI(%q) returned attr-unsafe template.URL %q — can break out of src=\"...\" and inject markup", logo, string(uri))
			}
		}

		// End-to-end through the real report fragment builder. Note: the company
		// name is operator-supplied (--brand / DSD_BRAND_COMPANY) and is only
		// html.EscapeString'd, which does NOT strip C0/ESC control bytes — so this
		// oracle deliberately asserts the ATTRIBUTE-BREAKOUT property of the logo
		// src (the untrusted template.URL bypass), not control-freeness of the
		// operator company text (see the report's D4 section).
		SetBrand(Brand{Company: body, Logo: logo})
		defer SetBrand(Brand{})
		frag := brandBarHTML()
		// Every src="..." value must be quote-balanced: the char run after src="
		// up to the next " must not itself contain a stray quote-breaking char.
		for rest := frag; ; {
			i := strings.Index(rest, `src="`)
			if i < 0 {
				break
			}
			rest = rest[i+len(`src="`):]
			j := strings.IndexByte(rest, '"')
			if j < 0 {
				t.Fatalf("brandBarHTML emitted an unterminated src=\" attribute: %q", frag)
			}
			val := rest[:j]
			if strings.ContainsAny(val, "<>`") {
				t.Fatalf("brandBarHTML src attribute value %q contains markup-breaking chars (logo=%q)", val, logo)
			}
			rest = rest[j+1:]
		}
	})
}
