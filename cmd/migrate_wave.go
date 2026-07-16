package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/source"
	"github.com/keyorixhq/dashdiag/internal/version"
)

var migrateWaveCmd = &cobra.Command{
	Use:   "wave [src:dst ...]",
	Short: "Certify a migration wave — all pairs in one engagement report",
	Long: `Certify a batch of source→destination bundle pairs and produce one engagement report.

Each pair is src.tar.gz:dst.tar.gz (colon-separated) or via --pairs-file (one pair
per line, whitespace-separated, # comments allowed).

Examples:
  dsd migrate wave vm01-src.tar.gz:vm01-dst.tar.gz vm02-src.tar.gz:vm02-dst.tar.gz
  dsd migrate wave --pairs-file wave.txt --report-html --name "Acme Corp July Wave"

Exit code: 2 if any pair FAILed, 1 if any PASS-WITH-WARNINGS, else 0.`,
	PersistentPreRun: func(_ *cobra.Command, _ []string) { /* suppress brand header */ },
	RunE:             runMigrateWave,
}

func init() {
	migrateCmd.AddCommand(migrateWaveCmd)
	migrateWaveCmd.Flags().String("pairs-file", "", "file with one src dst pair per line (# comments allowed)")
	migrateWaveCmd.Flags().String("name", "", "engagement/wave name for the report header")
	migrateWaveCmd.Flags().Bool("report-html", false, "write a self-contained wave HTML report to dsd-migration-wave-<date>.html")
	migrateWaveCmd.Flags().Bool("json", false, "machine-readable wave result")
	migrateWaveCmd.Flags().Bool("deep", false, "replay deep collectors for each pair")
	migrateWaveCmd.Flags().Bool("pkg", false, "replay the package collector for each pair")
	migrateWaveCmd.Flags().Bool("force", false, "certify even if a bundle's OS differs from this binary")
}

type wavePair struct {
	Src string
	Dst string
}

type waveResult struct {
	Pair        wavePair
	SrcBundle   *source.Bundle
	DstBundle   *source.Bundle
	Verdict     string
	Regressions []baseline.DiffEntry
	Err         error
}

func runMigrateWave(cmd *cobra.Command, args []string) error {
	applyBrand(cmd)
	pairsFile, _ := cmd.Flags().GetString("pairs-file")
	pairs, err := resolvePairs(args, pairsFile)
	if err != nil {
		return err
	}
	if len(pairs) == 0 {
		return fmt.Errorf("no pairs given — pass src:dst args or --pairs-file")
	}
	force, _ := cmd.Flags().GetBool("force")
	deep, _ := cmd.Flags().GetBool("deep")
	pkg, _ := cmd.Flags().GetBool("pkg")
	jsonOut, _ := cmd.Flags().GetBool("json")
	engName, _ := cmd.Flags().GetString("name")
	reportHTML, _ := cmd.Flags().GetBool("report-html")

	if !jsonOut {
		fmt.Fprintf(os.Stderr, "Certifying %d pair(s)…\n", len(pairs))
	}
	results := certifyWave(pairs, force, deep, pkg, jsonOut)

	if jsonOut {
		return emitWaveJSON(results, engName)
	}
	printWaveTable(results, engName)
	if reportHTML {
		path, rerr := render.GenerateWaveHTMLReport(buildWaveReport(results, engName))
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "wave report: %v\n", rerr)
		} else {
			fmt.Fprintf(os.Stderr, "\n📄 Wave HTML report saved: %s\n", path)
		}
	}
	switch waveWorstVerdict(results) {
	case certFail:
		recordExitCode(2)
	case certWarn:
		recordExitCode(1)
	}
	return nil
}

func certifyWave(pairs []wavePair, force, deep, pkg, quiet bool) []waveResult {
	results := make([]waveResult, 0, len(pairs))
	for _, p := range pairs {
		r := certifyPair(p, force, deep, pkg)
		if !quiet && r.Verdict != "" {
			mark := map[string]string{certPass: "✅", certWarn: "⚠️", certFail: "❌"}[r.Verdict]
			fmt.Fprintf(os.Stderr, "  %s  %-22s → %-22s  %s\n",
				mark, manifestHost(r.SrcBundle), manifestHost(r.DstBundle), r.Verdict)
		}
		results = append(results, r)
	}
	return results
}

func certifyPair(p wavePair, force, deep, pkg bool) waveResult {
	r := waveResult{Pair: p}
	var err error
	r.SrcBundle, err = loadBundle(p.Src)
	if err != nil {
		r.Err = fmt.Errorf("loading source %q: %w", p.Src, err)
		r.Verdict = certFail
		return r
	}
	r.DstBundle, err = loadBundle(p.Dst)
	if err != nil {
		r.Err = fmt.Errorf("loading destination %q: %w", p.Dst, err)
		r.Verdict = certFail
		return r
	}
	if err = replayPlatformGuard(r.SrcBundle, force); err != nil {
		r.Err = err
		r.Verdict = certFail
		return r
	}
	if err = replayPlatformGuard(r.DstBundle, force); err != nil {
		r.Err = err
		r.Verdict = certFail
		return r
	}
	_, _, srcSnap := replayBundle(r.SrcBundle, deep, pkg, false, false)
	_, _, dstSnap := replayBundle(r.DstBundle, deep, pkg, false, false)
	diff := baseline.ComputeDiff(srcSnap, dstSnap)
	r.Verdict, r.Regressions = certifyVerdict(diff)
	return r
}

func waveWorstVerdict(results []waveResult) string {
	worst := certPass
	for _, r := range results {
		if r.Verdict == certFail {
			return certFail
		}
		if r.Verdict == certWarn {
			worst = certWarn
		}
	}
	return worst
}

func printWaveTable(results []waveResult, name string) {
	pass, warn, fail := 0, 0, 0
	for _, r := range results {
		switch r.Verdict {
		case certFail:
			fail++
		case certWarn:
			warn++
		default:
			pass++
		}
	}
	if name != "" {
		fmt.Printf("\nWave: %s\n", name)
	}
	fmt.Printf("\n%d pair(s): %d PASS · %d PASS-WITH-WARNINGS · %d FAIL\n",
		len(results), pass, warn, fail)
}

func resolvePairs(args []string, pairsFile string) ([]wavePair, error) {
	var pairs []wavePair
	for _, arg := range args {
		src, dst, ok := strings.Cut(arg, ":")
		if !ok {
			return nil, fmt.Errorf("pair argument %q: expected src:dst (colon-separated)", arg)
		}
		pairs = append(pairs, wavePair{Src: src, Dst: dst})
	}
	if pairsFile == "" {
		return pairs, nil
	}
	f, err := os.Open(pairsFile)
	if err != nil {
		return nil, fmt.Errorf("reading --pairs-file: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("pairs file line %q: expected two fields (src dst)", line)
		}
		pairs = append(pairs, wavePair{Src: fields[0], Dst: fields[1]})
	}
	return pairs, sc.Err()
}

type waveJSON struct {
	Name    string         `json:"name,omitempty"`
	Verdict string         `json:"verdict"`
	Date    string         `json:"date"`
	Total   int            `json:"total"`
	Counts  waveCounts     `json:"counts"`
	Pairs   []wavePairJSON `json:"pairs"`
}

type waveCounts struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

type wavePairJSON struct {
	Source      certifyEndpoint     `json:"source"`
	Destination certifyEndpoint     `json:"destination"`
	Verdict     string              `json:"verdict"`
	Regressions []certifyRegression `json:"regressions"`
	Error       string              `json:"error,omitempty"`
}

func emitWaveJSON(results []waveResult, name string) error {
	out := waveJSON{
		Name:    name,
		Verdict: waveWorstVerdict(results),
		Date:    time.Now().UTC().Format(time.RFC3339),
		Total:   len(results),
	}
	for _, r := range results {
		pj := wavePairJSON{Verdict: r.Verdict}
		if r.SrcBundle != nil {
			pj.Source = certifyEndpoint{Host: manifestHost(r.SrcBundle), OS: manifestOS(r.SrcBundle), Created: r.SrcBundle.Manifest.Created}
		}
		if r.DstBundle != nil {
			pj.Destination = certifyEndpoint{Host: manifestHost(r.DstBundle), OS: manifestOS(r.DstBundle), Created: r.DstBundle.Manifest.Created}
		}
		if r.Err != nil {
			pj.Error = r.Err.Error()
		}
		for _, reg := range r.Regressions {
			pj.Regressions = append(pj.Regressions, certifyRegression{Name: reg.Name, Before: firstToken(reg.Before), After: firstToken(reg.After)})
		}
		switch r.Verdict {
		case certFail:
			out.Counts.Fail++
		case certWarn:
			out.Counts.Warn++
		default:
			out.Counts.Pass++
		}
		out.Pairs = append(out.Pairs, pj)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	switch out.Verdict {
	case certFail:
		recordExitCode(2)
	case certWarn:
		recordExitCode(1)
	}
	return nil
}

func buildWaveReport(results []waveResult, name string) render.WaveReport {
	now := time.Now()
	report := render.WaveReport{
		Name:    name,
		Date:    now.Format("2006-01-02 15:04:05 MST"),
		Version: version.Version,
		Year:    now.Year(),
		Total:   len(results),
	}
	for _, r := range results {
		row := render.WavePairRow{
			Verdict:      r.Verdict,
			VerdictClass: waveVerdictClass(r.Verdict),
		}
		if r.SrcBundle != nil {
			row.Source = manifestHost(r.SrcBundle)
			row.SourceOS = manifestOS(r.SrcBundle)
		}
		if r.DstBundle != nil {
			row.Destination = manifestHost(r.DstBundle)
			row.DestOS = manifestOS(r.DstBundle)
		}
		if r.Err != nil {
			row.VerdictClass = "error"
			row.Error = r.Err.Error()
		} else if len(r.Regressions) > 0 {
			row.RegressionCount = len(r.Regressions)
			row.TopRegression = r.Regressions[0].Name
		}
		switch r.Verdict {
		case certFail:
			report.CountFail++
		case certWarn:
			report.CountWarn++
		default:
			report.CountPass++
		}
		report.Pairs = append(report.Pairs, row)
	}
	verdict := waveWorstVerdict(results)
	report.Verdict = verdict
	report.VerdictClass = waveVerdictClass(verdict)
	switch verdict {
	case certFail:
		report.VerdictText = fmt.Sprintf("%d pair(s) failed certification — regressions detected.", report.CountFail)
	case certWarn:
		report.VerdictText = fmt.Sprintf("%d pair(s) passed with warnings — review recommended.", report.CountWarn)
	default:
		report.VerdictText = "All pairs passed certification — the migration wave is clean."
	}
	report.Consequences = waveConsequences(results)
	return report
}

func waveVerdictClass(verdict string) string {
	switch verdict {
	case certFail:
		return "crit"
	case certWarn:
		return "warn"
	default:
		return "ok"
	}
}
