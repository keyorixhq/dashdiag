package render

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"
)

// FleetReport is the view model for the fleet HTML report. It is populated by
// the cmd layer (which can import both render and fleet) so that render itself
// never needs to import the fleet package — preserving the one-way layer graph.
type FleetReport struct {
	Date             string
	Version          string
	Verdict          string // OK | WARN | CRIT
	VerdictClass     string // ok | warn | crit
	VerdictText      string
	Total            int
	CountOK          int
	CountWarn        int
	CountCrit        int
	CountUnreachable int
	Hosts            []FleetHostRow
	Issues           []FleetIssueRow
	Consequences     []string
	Year             int
	BrandName        string
	BrandLogo        template.URL
}

// FleetHostRow is one row in the per-host table.
type FleetHostRow struct {
	Host        string
	Hostname    string // as self-reported by the remote dsd (may differ from Host)
	Status      string // OK | WARN | CRIT | UNREACHABLE
	StatusClass string // ok | warn | crit | error
	Crit        int
	Warn        int
	TopIssue    string
	ElapsedMs   int64
}

// FleetIssueRow is one row in the cross-host grouped-issues table.
type FleetIssueRow struct {
	Scope      string // fleet-wide | common | outlier
	ScopeClass string // fleetwide | common | outlier  (for CSS, no hyphen)
	Level      string // CRIT | WARN
	LevelClass string // crit | warn
	Check      string
	Where      string // "3/5" ratio or hostname for a single-host outlier
	Sample     string
}

// buildFleetHTML renders the fleet report to an HTML string without writing it to disk.
// Brand state is applied inside (reads the global brandOverride / env vars).
func buildFleetHTML(report FleetReport) (string, error) {
	if report.Year == 0 {
		report.Year = time.Now().Year()
	}
	b := activeBrand()
	if b.Company != "" || b.Logo != "" {
		report.BrandName = b.Company
		report.BrandLogo = logoDataURI(b.Logo)
	}
	var buf bytes.Buffer
	if err := fleetHTMLTmpl.Execute(&buf, report); err != nil {
		return "", fmt.Errorf("rendering fleet report: %w", err)
	}
	return buf.String(), nil
}

// GenerateFleetHTMLReport renders a self-contained fleet HTML report and writes
// it to dsd-fleet-report-<timestamp>.html in the current directory. Returns the
// path of the written file.
func GenerateFleetHTMLReport(report FleetReport) (string, error) {
	html, err := buildFleetHTML(report)
	if err != nil {
		return "", err
	}
	ts := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("dsd-fleet-report-%s.html", ts)
	path := filepath.Join(".", filename)
	if err := os.WriteFile(path, []byte(html), 0o644); err != nil { //nolint:gosec // report file, world-readable intentional
		return "", fmt.Errorf("writing fleet report: %w", err)
	}
	return path, nil
}

var fleetHTMLTmpl = template.Must(template.New("fleet").Parse(fleetHTMLTemplate))

const fleetHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .BrandName}}{{.BrandName}} — Fleet Health Report{{else}}DashDiag Fleet Health Report{{end}}</title>
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
  .wrap { max-width: 960px; margin: 0 auto; padding: 32px 24px 64px; }
  header { border-bottom: 2px solid var(--line); padding-bottom: 18px; margin-bottom: 24px; }
  h1 { font-size: 22px; margin: 0 0 4px; letter-spacing: -0.01em; }
  h2 { font-size: 17px; margin: 32px 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--line); }
  .meta { color: var(--muted); font-size: 13px; }
  .meta b { color: var(--ink); font-weight: 600; }
  .meta code { background: #eef1f3; padding: 1px 6px; border-radius: 4px; font-size: 12px; }
  .brandbar { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }
  .brand-logo { max-height: 44px; max-width: 220px; object-fit: contain; }
  .brand-name { font-size: 18px; font-weight: 700; color: var(--ink); letter-spacing: -0.01em; }
  .verdict { margin: 22px 0; padding: 18px 22px; border-radius: 10px; border-left: 6px solid; }
  .verdict .badge { font-weight: 700; font-size: 18px; letter-spacing: 0.02em; }
  .verdict p { margin: 6px 0 0; font-size: 14px; }
  .verdict.crit { background: var(--crit-bg); border-color: var(--crit); } .verdict.crit .badge { color: var(--crit); }
  .verdict.warn { background: var(--warn-bg); border-color: var(--warn); } .verdict.warn .badge { color: var(--warn); }
  .verdict.ok   { background: var(--ok-bg);   border-color: var(--ok);   } .verdict.ok .badge   { color: var(--ok); }
  .chips { display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap; }
  .chip { font-size: 13px; font-weight: 600; padding: 4px 12px; border-radius: 20px; border: 1px solid var(--line); background: #fff; }
  .chip.crit { color: var(--crit); } .chip.warn { color: var(--warn); } .chip.ok { color: var(--ok); } .chip.muted { color: var(--muted); }
  table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid var(--line);
    border-radius: 8px; overflow: hidden; margin-bottom: 8px; }
  th, td { text-align: left; padding: 9px 14px; border-bottom: 1px solid var(--line); font-size: 14px; }
  th { background: #fafbfc; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.03em; }
  tr:last-child td { border-bottom: none; }
  td .detail { color: var(--muted); font-size: 13px; }
  .st { font-weight: 700; font-size: 12px; padding: 2px 9px; border-radius: 4px; white-space: nowrap; }
  .st.crit  { color: var(--crit); background: var(--crit-bg); }
  .st.warn  { color: var(--warn); background: var(--warn-bg); }
  .st.ok    { color: var(--ok);   background: var(--ok-bg);   }
  .st.error { color: var(--muted); background: #f0f2f4; }
  .scope { font-size: 11px; font-weight: 600; padding: 2px 7px; border-radius: 4px;
    background: #eef1f3; color: var(--muted); white-space: nowrap; }
  .scope.fleetwide { background: #fdecea; color: var(--crit); }
  .scope.common    { background: var(--warn-bg); color: var(--warn); }
  .ok-note { color: var(--ok); font-weight: 600; }
  .consequences ul { margin: 8px 0 0; padding-left: 22px; }
  .consequences li { margin-bottom: 4px; font-size: 14px; color: var(--ink); }
  footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--line);
    color: var(--muted); font-size: 12px; }
  footer a { color: var(--muted); }
  @media print {
    @page { size: A4; margin: 14mm; }
    html, body { background: #fff; }
    body { font-size: 12px; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .verdict, .chip, .st, .scope { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .wrap { max-width: none; margin: 0; padding: 0; }
    h1, h2 { break-after: avoid; }
    h2 { margin-top: 20px; }
    table, tr { break-inside: avoid; }
    a { color: var(--ink); text-decoration: none; }
    footer { margin-top: 24px; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header>
    {{if or .BrandName .BrandLogo}}<div class="brandbar">{{if .BrandLogo}}<img class="brand-logo" src="{{.BrandLogo}}" alt="{{.BrandName}}">{{end}}{{if .BrandName}}<span class="brand-name">{{.BrandName}}</span>{{end}}</div>{{end}}
    <h1>{{if .BrandName}}Fleet Health Report{{else}}DashDiag Fleet Health Report{{end}}</h1>
    <div class="meta">
      <b>Date:</b> {{.Date}} &nbsp;·&nbsp;
      <b>Hosts:</b> {{.Total}} &nbsp;·&nbsp;
      <b>dsd:</b> {{.Version}}
    </div>
  </header>

  <div class="verdict {{.VerdictClass}}">
    <span class="badge">{{.Verdict}}</span>
    <p>{{.VerdictText}}</p>
    <div class="chips">
      <span class="chip ok">{{.CountOK}} healthy</span>
      <span class="chip warn">{{.CountWarn}} warning</span>
      <span class="chip crit">{{.CountCrit}} critical</span>
      {{if .CountUnreachable}}<span class="chip muted">{{.CountUnreachable}} unreachable</span>{{end}}
    </div>
  </div>

  {{if .Consequences}}
  <h2>What This Means</h2>
  <div class="consequences">
    <ul>
    {{range .Consequences}}<li>{{.}}</li>
    {{end}}</ul>
  </div>
  {{end}}

  {{if .Issues}}
  <h2>Fleet Issues</h2>
  <table>
    <thead><tr><th>Scope</th><th>Level</th><th>Check</th><th>Hosts</th><th>Issue</th></tr></thead>
    <tbody>
    {{range .Issues}}
      <tr>
        <td><span class="scope {{.ScopeClass}}">{{.Scope}}</span></td>
        <td><span class="st {{.LevelClass}}">{{.Level}}</span></td>
        <td>{{.Check}}</td>
        <td><span class="detail">{{.Where}}</span></td>
        <td><span class="detail">{{.Sample}}</span></td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  <h2>Hosts</h2>
  <table>
    <thead><tr><th>Host</th><th>Status</th><th>Crit</th><th>Warn</th><th>Time</th><th>Top Issue</th></tr></thead>
    <tbody>
    {{range .Hosts}}
      <tr>
        <td>{{.Host}}{{if and .Hostname (ne .Hostname .Host)}}<br><span class="detail">{{.Hostname}}</span>{{end}}</td>
        <td><span class="st {{.StatusClass}}">{{.Status}}</span></td>
        <td>{{if .Crit}}<span style="color:var(--crit);font-weight:700">{{.Crit}}</span>{{else}}<span class="detail">0</span>{{end}}</td>
        <td>{{if .Warn}}<span style="color:var(--warn);font-weight:600">{{.Warn}}</span>{{else}}<span class="detail">0</span>{{end}}</td>
        <td><span class="detail">{{.ElapsedMs}}ms</span></td>
        <td><span class="detail">{{.TopIssue}}</span></td>
      </tr>
    {{end}}
    </tbody>
  </table>

  <footer>
    {{if .BrandName}}Prepared by <b>{{.BrandName}}</b> · powered by <a href="https://dashdiag.sh">DashDiag</a> {{.Version}} · © {{.Year}}{{else}}Generated by <a href="https://github.com/keyorixhq/dashdiag">DashDiag</a> {{.Version}} · © {{.Year}} · <a href="https://dashdiag.sh">dashdiag.sh</a>{{end}}
  </footer>
</div>
</body>
</html>
`
