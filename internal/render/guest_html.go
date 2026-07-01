package render

import (
	"fmt"
	"html"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// GuestReportBlock is one titled section of the focused two-block guest report
// (e.g. "Your instance — you can fix these" / "AWS-imposed limits — evidence …").
type GuestReportBlock struct {
	Title  string
	Issues []models.Insight
}

// GuestReportHTML renders the `dsd guest` / `dsd <platform>` two-block view as a
// self-contained, printable HTML artifact — the co-brandable leave-behind a tenant
// can hand whoever runs their platform. Inline CSS only (no external assets), so it
// renders offline and survives email. verdictLevel is "ok" | "warn" | "crit".
func GuestReportHTML(identity, hostname, generated string, blocks []GuestReportBlock, verdictLevel, verdictText string) string {
	var b strings.Builder
	b.WriteString(guestReportHead)
	b.WriteString(brandBarHTML())
	fmt.Fprintf(&b, "<h1>%s</h1>\n", html.EscapeString(identity))
	fmt.Fprintf(&b, `<div class="meta"><b>Host:</b> <code>%s</code> &nbsp;·&nbsp; <b>Generated:</b> %s</div>`+"\n",
		html.EscapeString(hostname), html.EscapeString(generated))
	b.WriteString("</header>\n")

	fmt.Fprintf(&b, `<div class="verdict %s"><span class="badge">%s</span></div>`+"\n",
		verdictClass(verdictLevel), html.EscapeString(verdictText))

	for _, blk := range blocks {
		fmt.Fprintf(&b, "<h2>%s</h2>\n", html.EscapeString(blk.Title))
		if len(blk.Issues) == 0 {
			b.WriteString(`<p class="ok-note">✓ nothing flagged</p>` + "\n")
			continue
		}
		for _, in := range blk.Issues {
			cls := "info"
			if l := strings.ToLower(in.Level); l == "warn" || l == "crit" {
				cls = l
			}
			fmt.Fprintf(&b, `<div class="issue %s"><span class="tag">%s</span> <span class="msg">%s</span>`,
				cls, html.EscapeString(in.Level), html.EscapeString(in.Message))
			if len(in.Hints) > 0 {
				b.WriteString(`<div class="fixlabel">Remediation</div><ul class="hints">`)
				for _, h := range in.Hints {
					fmt.Fprintf(&b, "<li>%s</li>", html.EscapeString(h))
				}
				b.WriteString("</ul>")
			}
			b.WriteString("</div>\n")
		}
	}
	b.WriteString(guestFooterHTML())
	return b.String()
}

// guestFooterHTML returns the guest report's footer + closing tags, branded when a
// company is set ("Prepared by X · powered by DashDiag") and the default dsd footer
// otherwise. Keeps a subtle DashDiag attribution in both cases.
func guestFooterHTML() string {
	if company := activeBrand().Company; company != "" {
		return fmt.Sprintf(`<footer>
  Prepared by <b>%s</b> · powered by <a href="https://dashdiag.sh">DashDiag</a>.
</footer>
</div>
</body>
</html>
`, html.EscapeString(company))
	}
	return guestReportFoot
}

func verdictClass(level string) string {
	switch strings.ToLower(level) {
	case "crit":
		return "crit"
	case "warn":
		return "warn"
	default:
		return "ok"
	}
}

const guestReportHead = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Guest Health Report</title>
<style>
  :root {
    --crit: #c0392b; --crit-bg: #fdecea;
    --warn: #b9770e; --warn-bg: #fef6e7;
    --ok:   #1e8449; --ok-bg:   #eafaf1;
    --ink:  #1a1f24; --muted: #6b7680; --line: #e3e8ec; --bg: #f5f7f9;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--ink);
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  .wrap { max-width: 860px; margin: 0 auto; padding: 32px 24px 64px; }
  header { border-bottom: 2px solid var(--line); padding-bottom: 18px; margin-bottom: 16px; }
  h1 { font-size: 21px; margin: 0 0 6px; letter-spacing: -0.01em; }
  h2 { font-size: 15px; margin: 30px 0 10px; padding-bottom: 6px; border-bottom: 1px solid var(--line); color: var(--muted); text-transform: none; }
  .meta { color: var(--muted); font-size: 13px; }
  .meta b { color: var(--ink); font-weight: 600; }
  .meta code { background: #eef1f3; padding: 1px 6px; border-radius: 4px; font-size: 12px; }
  .brandbar { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }
  .brand-logo { max-height: 44px; max-width: 220px; object-fit: contain; }
  .brand-name { font-size: 18px; font-weight: 700; color: var(--ink); letter-spacing: -0.01em; }
  .verdict { margin: 20px 0; padding: 16px 20px; border-radius: 10px; border-left: 6px solid; }
  .verdict .badge { font-weight: 700; font-size: 16px; }
  .verdict.crit { background: var(--crit-bg); border-color: var(--crit); } .verdict.crit .badge { color: var(--crit); }
  .verdict.warn { background: var(--warn-bg); border-color: var(--warn); } .verdict.warn .badge { color: var(--warn); }
  .verdict.ok   { background: var(--ok-bg);   border-color: var(--ok);   } .verdict.ok .badge   { color: var(--ok); }
  .issue { background: #fff; border: 1px solid var(--line); border-left: 5px solid; border-radius: 8px; padding: 13px 16px; margin: 10px 0; }
  .issue.crit { border-left-color: var(--crit); } .issue.warn { border-left-color: var(--warn); } .issue.info { border-left-color: var(--muted); }
  .issue .tag { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; padding: 2px 8px; border-radius: 4px; color: #fff; }
  .issue.crit .tag { background: var(--crit); } .issue.warn .tag { background: var(--warn); } .issue.info .tag { background: var(--muted); }
  .issue .msg { font-weight: 500; }
  .issue .fixlabel { font-size: 12px; font-weight: 600; color: var(--muted); margin-top: 10px; }
  .hints { margin: 4px 0 0; padding-left: 20px; } .hints li { font-size: 13.5px; margin: 3px 0; color: var(--ink); }
  .ok-note { color: var(--ok); font-weight: 600; margin: 8px 0; }
  footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12px; }
  footer a { color: var(--muted); }
  @media print {
    @page { size: A4; margin: 14mm; }
    html, body { background: #fff; }
    body { font-size: 12px; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .verdict, .tag, .issue { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .wrap { max-width: none; margin: 0; padding: 0; }
    h1, h2 { break-after: avoid; }
    .verdict, .issue { break-inside: avoid; }
    a { color: var(--ink); text-decoration: none; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header>
`

const guestReportFoot = `<footer>
  Generated by <a href="https://dashdiag.sh">DashDiag</a> · guest-side health, split into what you can fix vs. evidence for whoever runs your platform.
</footer>
</div>
</body>
</html>
`
