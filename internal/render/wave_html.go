package render

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"
)

// WaveReport is the view model for the migration-wave HTML report. Populated by
// the cmd layer so that render never imports baseline or source packages.
type WaveReport struct {
	Name         string
	Date         string
	Version      string
	Year         int
	Verdict      string // PASS | PASS-WITH-WARNINGS | FAIL
	VerdictClass string // ok | warn | crit
	VerdictText  string
	Total        int
	CountPass    int
	CountWarn    int
	CountFail    int
	Pairs        []WavePairRow
	Consequences []string
	BrandName    string
	BrandLogo    template.URL
}

// WavePairRow is one source→destination pair in the pair table.
type WavePairRow struct {
	Source          string
	SourceOS        string
	Destination     string
	DestOS          string
	Verdict         string // PASS | PASS-WITH-WARNINGS | FAIL | ERROR
	VerdictClass    string // ok | warn | crit | error
	RegressionCount int
	TopRegression   string
	Error           string // set when bundle load/replay failed
}

// buildWaveHTML renders the wave report to a string without writing it to disk.
func buildWaveHTML(report WaveReport) (string, error) {
	if report.Year == 0 {
		report.Year = time.Now().Year()
	}
	b := activeBrand()
	if b.Company != "" || b.Logo != "" {
		report.BrandName = b.Company
		report.BrandLogo = logoDataURI(b.Logo)
	}
	var buf bytes.Buffer
	if err := waveHTMLTmpl.Execute(&buf, report); err != nil {
		return "", fmt.Errorf("rendering wave report: %w", err)
	}
	return buf.String(), nil
}

// GenerateWaveHTMLReport renders a self-contained wave HTML report and writes it
// to dsd-migration-wave-<timestamp>.html in the current directory.
func GenerateWaveHTMLReport(report WaveReport) (string, error) {
	html, err := buildWaveHTML(report)
	if err != nil {
		return "", err
	}
	ts := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("dsd-migration-wave-%s.html", ts)
	path := filepath.Join(".", filename)
	if err := os.WriteFile(path, []byte(html), 0o644); err != nil { //nolint:gosec // report file, world-readable intentional
		return "", fmt.Errorf("writing wave report: %w", err)
	}
	return path, nil
}

var waveHTMLTmpl = template.Must(template.New("wave").Parse(waveHTMLTemplate))

const waveHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .BrandName}}{{.BrandName}} — {{end}}{{if .Name}}{{.Name}}{{else}}Migration Wave Certification{{end}}</title>
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
  .chip.crit { color: var(--crit); } .chip.warn { color: var(--warn); } .chip.ok { color: var(--ok); }
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
  .arrow { color: var(--muted); font-size: 13px; padding: 0 4px; }
  .consequences ul { margin: 8px 0 0; padding-left: 22px; }
  .consequences li { margin-bottom: 4px; font-size: 14px; color: var(--ink); }
  footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--line);
    color: var(--muted); font-size: 12px; }
  footer a { color: var(--muted); }
  @media print {
    @page { size: A4; margin: 14mm; }
    html, body { background: #fff; }
    body { font-size: 12px; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .verdict, .chip, .st { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
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
    <h1>{{if .Name}}{{.Name}}{{else}}Migration Wave Certification{{end}}</h1>
    <div class="meta">
      <b>Date:</b> {{.Date}} &nbsp;·&nbsp;
      <b>Pairs:</b> {{.Total}} &nbsp;·&nbsp;
      <b>dsd:</b> {{.Version}}
    </div>
  </header>

  <div class="verdict {{.VerdictClass}}">
    <span class="badge">{{.Verdict}}</span>
    <p>{{.VerdictText}}</p>
    <div class="chips">
      <span class="chip ok">{{.CountPass}} PASS</span>
      <span class="chip warn">{{.CountWarn}} PASS-WITH-WARNINGS</span>
      <span class="chip crit">{{.CountFail}} FAIL</span>
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

  <h2>Certification Results</h2>
  <table>
    <thead><tr><th>Source</th><th>Destination</th><th>Verdict</th><th>Regressions</th><th>Top Regression / Error</th></tr></thead>
    <tbody>
    {{range .Pairs}}
      <tr>
        <td>{{.Source}}{{if .SourceOS}}<br><span class="detail">{{.SourceOS}}</span>{{end}}</td>
        <td>{{.Destination}}{{if .DestOS}}<br><span class="detail">{{.DestOS}}</span>{{end}}</td>
        <td><span class="st {{.VerdictClass}}">{{.Verdict}}</span></td>
        <td>{{if .RegressionCount}}<span style="color:var(--crit);font-weight:700">{{.RegressionCount}}</span>{{else}}<span class="detail">—</span>{{end}}</td>
        <td><span class="detail">{{if .Error}}{{.Error}}{{else}}{{.TopRegression}}{{end}}</span></td>
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
