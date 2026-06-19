package render

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/version"
)

// GenerateHTMLReport produces a self-contained, exec-readable HTML health report
// and writes it to dsd-report-<host>-<date>.html. Self-contained (inline CSS, no
// external assets) so it opens in any browser offline and prints cleanly to PDF —
// the artifact a customer hands to management after a pilot run. Mirrors the
// markdown report (GenerateReport) but formatted for a non-engineer audience.
// Returns the output file path.
func GenerateHTMLReport(snap *baseline.Snapshot, insights []models.Insight, elapsed time.Duration, cve *models.CVEAllResult) (string, error) {
	if snap == nil {
		return "", fmt.Errorf("no snapshot data")
	}

	html, err := buildHTML(snap, insights, elapsed, cve)
	if err != nil {
		return "", err
	}

	timestamp := snap.Timestamp.Format("20060102-150405")
	filename := fmt.Sprintf("dsd-report-%s-%s.html", snap.Hostname, timestamp)
	path := filepath.Join(".", filename)

	if err := os.WriteFile(path, []byte(html), 0o644); err != nil { //nolint:gosec // report file, world-readable intentional
		return "", fmt.Errorf("writing report: %w", err)
	}
	return path, nil
}

// htmlReportData is the view model handed to the template.
type htmlReportData struct {
	Hostname     string
	Date         string
	ScanTime     string
	Version      string
	Verdict      string // OK | WARN | CRIT
	VerdictClass string
	VerdictText  string
	Crit         int
	Warn         int
	Info         int
	Issues       []htmlIssue
	Checks       []htmlCheckRow
	CVE          *htmlCVE
	Year         int
}

type htmlIssue struct {
	Level      string
	LevelClass string
	Check      string
	Message    string
	Hints      []string
}

type htmlCheckRow struct {
	Name        string
	Status      string
	StatusClass string
	Detail      string
}

type htmlCVE struct {
	Manager    string
	Total      int
	Critical   []htmlAdvisory
	Important  []htmlAdvisory
	Moderate   []htmlAdvisory
	Low        []htmlAdvisory
	FixCommand string
}

type htmlAdvisory struct {
	ID      string
	Summary string
}

func buildHTML(snap *baseline.Snapshot, insights []models.Insight, elapsed time.Duration, cve *models.CVEAllResult) (string, error) {
	crit := countLevel(insights, "CRIT")
	warn := countLevel(insights, "WARN")
	info := countLevel(insights, "INFO")

	data := htmlReportData{
		Hostname: snap.Hostname,
		Date:     snap.Timestamp.Format("2006-01-02 15:04:05 MST"),
		ScanTime: fmt.Sprintf("%.1fs", elapsed.Seconds()),
		Version:  version.Version,
		Crit:     crit,
		Warn:     warn,
		Info:     info,
		Year:     snap.Timestamp.Year(),
	}

	switch {
	case crit > 0:
		data.Verdict, data.VerdictClass = "CRITICAL", "crit"
		data.VerdictText = fmt.Sprintf("%d critical issue(s) require immediate attention.", crit)
	case warn > 0:
		data.Verdict, data.VerdictClass = "WARNING", "warn"
		data.VerdictText = fmt.Sprintf("%d warning(s) found — review recommended.", warn)
	default:
		data.Verdict, data.VerdictClass = "HEALTHY", "ok"
		data.VerdictText = "All checks passed — system is healthy."
	}

	for _, ins := range filterActionable(insights) {
		cls := "warn"
		if ins.Level == "CRIT" {
			cls = "crit"
		}
		data.Issues = append(data.Issues, htmlIssue{
			Level: ins.Level, LevelClass: cls, Check: ins.Check, Message: ins.Message, Hints: ins.Hints,
		})
	}

	data.Checks = buildHTMLCheckRows(snap)

	if cve != nil && cve.PackageManager != "" {
		data.CVE = buildHTMLCVE(cve)
	}

	var buf bytes.Buffer
	if err := htmlReportTmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("rendering report: %w", err)
	}
	return buf.String(), nil
}

// buildHTMLCheckRows mirrors the markdown report's table: trust the snapshot's
// per-check worst status, ordered CRIT → WARN → OK then alphabetical (deterministic).
func buildHTMLCheckRows(snap *baseline.Snapshot) []htmlCheckRow {
	type row struct {
		htmlCheckRow
		rank int
	}
	rows := make([]row, 0, len(snap.Checks))
	for _, c := range snap.Checks {
		r := row{htmlCheckRow{Name: c.Name, Detail: c.Value}, 0}
		switch c.Status {
		case "CRIT":
			r.Status, r.StatusClass, r.rank = "CRIT", "crit", 2
		case "WARN":
			r.Status, r.StatusClass, r.rank = "WARN", "warn", 1
		default:
			r.Status, r.StatusClass, r.rank = "OK", "ok", 0
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].rank != rows[j].rank {
			return rows[i].rank > rows[j].rank
		}
		return rows[i].Name < rows[j].Name
	})
	out := make([]htmlCheckRow, len(rows))
	for i, r := range rows {
		out[i] = r.htmlCheckRow
	}
	return out
}

func buildHTMLCVE(cve *models.CVEAllResult) *htmlCVE {
	conv := func(as []models.CVEAdvisory) []htmlAdvisory {
		out := make([]htmlAdvisory, 0, len(as))
		for _, a := range as {
			out = append(out, htmlAdvisory{ID: a.ID, Summary: a.Summary})
		}
		return out
	}
	return &htmlCVE{
		Manager:    cve.PackageManager,
		Total:      len(cve.Critical) + len(cve.Important) + len(cve.Moderate) + len(cve.Low),
		Critical:   conv(cve.Critical),
		Important:  conv(cve.Important),
		Moderate:   conv(cve.Moderate),
		Low:        conv(cve.Low),
		FixCommand: cve.FixCommand,
	}
}

var htmlReportTmpl = template.Must(template.New("report").Parse(htmlReportTemplate))

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DashDiag Health Report — {{.Hostname}}</title>
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
  .wrap { max-width: 900px; margin: 0 auto; padding: 32px 24px 64px; }
  header { border-bottom: 2px solid var(--line); padding-bottom: 18px; margin-bottom: 24px; }
  h1 { font-size: 22px; margin: 0 0 4px; letter-spacing: -0.01em; }
  h2 { font-size: 17px; margin: 32px 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--line); }
  .meta { color: var(--muted); font-size: 13px; }
  .meta b { color: var(--ink); font-weight: 600; }
  .meta code { background: #eef1f3; padding: 1px 6px; border-radius: 4px; font-size: 12px; }
  .verdict { margin: 22px 0; padding: 18px 22px; border-radius: 10px; border-left: 6px solid; }
  .verdict .badge { font-weight: 700; font-size: 18px; letter-spacing: 0.02em; }
  .verdict p { margin: 6px 0 0; font-size: 14px; }
  .verdict.crit { background: var(--crit-bg); border-color: var(--crit); } .verdict.crit .badge { color: var(--crit); }
  .verdict.warn { background: var(--warn-bg); border-color: var(--warn); } .verdict.warn .badge { color: var(--warn); }
  .verdict.ok   { background: var(--ok-bg);   border-color: var(--ok);   } .verdict.ok .badge   { color: var(--ok); }
  .chips { display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap; }
  .chip { font-size: 13px; font-weight: 600; padding: 4px 12px; border-radius: 20px; border: 1px solid var(--line); background: #fff; }
  .chip.crit { color: var(--crit); } .chip.warn { color: var(--warn); } .chip.info { color: var(--muted); }
  .issue { background: #fff; border: 1px solid var(--line); border-left: 5px solid; border-radius: 8px;
    padding: 14px 18px; margin: 12px 0; }
  .issue.crit { border-left-color: var(--crit); } .issue.warn { border-left-color: var(--warn); }
  .issue .tag { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em;
    padding: 2px 8px; border-radius: 4px; color: #fff; }
  .issue.crit .tag { background: var(--crit); } .issue.warn .tag { background: var(--warn); }
  .issue .check { font-weight: 600; margin-left: 8px; }
  .issue .msg { margin: 10px 0 0; }
  .issue pre { background: #1a1f24; color: #e6edf3; border-radius: 6px; padding: 12px 14px;
    overflow-x: auto; font-size: 12.5px; margin: 12px 0 0; }
  .issue .fixlabel { font-size: 12px; font-weight: 600; color: var(--muted); margin-top: 12px; }
  table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid var(--line);
    border-radius: 8px; overflow: hidden; }
  th, td { text-align: left; padding: 9px 14px; border-bottom: 1px solid var(--line); font-size: 14px; }
  th { background: #fafbfc; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.03em; }
  tr:last-child td { border-bottom: none; }
  td .detail { color: var(--muted); font-size: 13px; }
  .st { font-weight: 700; font-size: 12px; padding: 2px 9px; border-radius: 4px; }
  .st.crit { color: var(--crit); background: var(--crit-bg); }
  .st.warn { color: var(--warn); background: var(--warn-bg); }
  .st.ok   { color: var(--ok);   background: var(--ok-bg); }
  .ok-note { color: var(--ok); font-weight: 600; }
  .cve-group { font-weight: 600; margin: 14px 0 6px; }
  .cve-list { margin: 0; padding-left: 20px; } .cve-list li { font-size: 13.5px; margin: 3px 0; }
  .cve-list code { background: #eef1f3; padding: 1px 5px; border-radius: 4px; }
  footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--line);
    color: var(--muted); font-size: 12px; }
  footer a { color: var(--muted); }
  @media print { body { background: #fff; } .wrap { max-width: none; } .issue, table { break-inside: avoid; } }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>DashDiag Health Report</h1>
    <div class="meta">
      <b>Host:</b> <code>{{.Hostname}}</code> &nbsp;·&nbsp;
      <b>Date:</b> {{.Date}} &nbsp;·&nbsp;
      <b>Scan time:</b> {{.ScanTime}} &nbsp;·&nbsp;
      <b>dsd:</b> {{.Version}}
    </div>
  </header>

  <div class="verdict {{.VerdictClass}}">
    <span class="badge">{{.Verdict}}</span>
    <p>{{.VerdictText}}</p>
    <div class="chips">
      <span class="chip crit">{{.Crit}} critical</span>
      <span class="chip warn">{{.Warn}} warning</span>
      <span class="chip info">{{.Info}} info</span>
    </div>
  </div>

  {{if .Issues}}
  <h2>Issues</h2>
  {{range .Issues}}
  <div class="issue {{.LevelClass}}">
    <span class="tag">{{.Level}}</span><span class="check">{{.Check}}</span>
    <p class="msg">{{.Message}}</p>
    {{if .Hints}}
    <div class="fixlabel">Remediation</div>
    <pre>{{range .Hints}}{{.}}
{{end}}</pre>
    {{end}}
  </div>
  {{end}}
  {{else}}
  <h2>Issues</h2>
  <p class="ok-note">No critical or warning issues found.</p>
  {{end}}

  <h2>Check Results</h2>
  <table>
    <thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
    <tbody>
    {{range .Checks}}
      <tr>
        <td>{{.Name}}</td>
        <td><span class="st {{.StatusClass}}">{{.Status}}</span></td>
        <td><span class="detail">{{.Detail}}</span></td>
      </tr>
    {{end}}
    </tbody>
  </table>

  {{with .CVE}}
  <h2>Security Advisories</h2>
  {{if eq .Total 0}}
  <p class="ok-note">No pending security advisories.</p>
  {{else}}
  <p><b>{{.Total}}</b> pending security advisor(ies) via <code>{{.Manager}}</code>.</p>
  {{if .Critical}}<div class="cve-group" style="color:var(--crit)">Critical ({{len .Critical}})</div>
  <ul class="cve-list">{{range .Critical}}<li><code>{{.ID}}</code> — {{.Summary}}</li>{{end}}</ul>{{end}}
  {{if .Important}}<div class="cve-group" style="color:var(--warn)">Important ({{len .Important}})</div>
  <ul class="cve-list">{{range .Important}}<li><code>{{.ID}}</code> — {{.Summary}}</li>{{end}}</ul>{{end}}
  {{if .Moderate}}<div class="cve-group">Moderate ({{len .Moderate}})</div>
  <ul class="cve-list">{{range .Moderate}}<li><code>{{.ID}}</code> — {{.Summary}}</li>{{end}}</ul>{{end}}
  {{if .Low}}<div class="cve-group">Low ({{len .Low}})</div>
  <ul class="cve-list">{{range .Low}}<li><code>{{.ID}}</code> — {{.Summary}}</li>{{end}}</ul>{{end}}
  {{if .FixCommand}}<p style="margin-top:12px">To fix all: <code>{{.FixCommand}}</code></p>{{end}}
  {{end}}
  {{end}}

  <footer>
    Generated by <a href="https://github.com/keyorixhq/dashdiag">DashDiag</a> {{.Version}}
    · © {{.Year}} · <a href="https://dashdiag.sh">dashdiag.sh</a>
  </footer>
</div>
</body>
</html>
`
