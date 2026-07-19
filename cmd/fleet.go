package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/fleet"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/version"
)

var fleetCmd = &cobra.Command{
	Use:   "fleet [host...]",
	Short: "Run dsd health across many hosts over SSH",
	Long: `Fan out 'dsd health' to a list of hosts over plain SSH and print an
aggregated verdict table. Free, local, no backend: it shells out to your system
ssh/scp, so it uses your ~/.ssh/config, keys, and agent. Nothing phones home.

Each host runs 'dsd health --json'; if dsd isn't installed there, pass --bin to
copy a local binary over first.

Hosts are [user@]host[:not-supported] strings (use ~/.ssh/config for ports/users).
Provide them as arguments and/or via --hosts-file (one per line, # comments ok).

Examples:
  dsd fleet web1 web2 db1
  dsd fleet --hosts-file hosts.txt
  dsd fleet --bin ./dist/dsd-linux-amd64 root@10.0.0.5 root@10.0.0.6
  dsd fleet --json web1 web2 | jq .verdict   # OK | WARN | CRIT (fleet-wide)

Exit code: 2 if any host is CRIT or unreachable, 1 if any WARN, else 0.`,
	RunE: runFleet,
}

func init() {
	rootCmd.AddCommand(fleetCmd)
	fleetCmd.Flags().String("hosts-file", "", "file with one host per line (# comments allowed)")
	fleetCmd.Flags().String("bin", "", "local dsd binary to scp to each host before running (for hosts without dsd)")
	fleetCmd.Flags().String("remote-cmd", "dsd health --json", "command to run on each host")
	fleetCmd.Flags().Duration("connect-timeout", 8*time.Second, "SSH connect timeout per host")
	fleetCmd.Flags().Duration("timeout", 45*time.Second, "overall timeout per host")
	fleetCmd.Flags().Int("concurrency", 8, "max hosts checked in parallel")
	fleetCmd.Flags().Bool("report-html", false, "write a self-contained fleet HTML report (printable to PDF) to dsd-fleet-report-<date>.html")
}

func runFleet(cmd *cobra.Command, args []string) error {
	hostsFile, _ := cmd.Flags().GetString("hosts-file")
	hosts, err := resolveHosts(args, hostsFile)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return fmt.Errorf("no hosts given — pass hosts as arguments or via --hosts-file")
	}

	binPath, _ := cmd.Flags().GetString("bin")
	if binPath != "" {
		if _, err := os.Stat(binPath); err != nil {
			return fmt.Errorf("--bin %q: %w", binPath, err)
		}
	}
	remoteCmd, _ := cmd.Flags().GetString("remote-cmd")
	connectTimeout, _ := cmd.Flags().GetDuration("connect-timeout")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	concurrency, _ := cmd.Flags().GetInt("concurrency")

	opts := fleet.Options{
		RemoteCmd:      remoteCmd,
		BinPath:        binPath,
		ConnectTimeout: connectTimeout,
		RunTimeout:     timeout,
		Concurrency:    concurrency,
	}

	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	mode := output.DetectMode(plain, false, "")

	if !jsonOut {
		fmt.Fprintf(os.Stderr, "Checking %d host(s)…\n", len(hosts))
	}
	results, err := fleet.Run(cmd.Context(), hosts, opts)
	if err != nil {
		return err
	}
	summary := fleet.Summarize(results)

	if jsonOut {
		data, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Println(string(data))
	} else {
		printFleetTable(summary, mode)
	}

	if reportHTML, _ := cmd.Flags().GetBool("report-html"); reportHTML {
		if path, err := render.GenerateFleetHTMLReport(buildFleetReport(summary)); err != nil {
			fmt.Fprintf(os.Stderr, "fleet report: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "\n📄 Fleet HTML report saved: %s\n", path)
		}
	}

	// Use the shared exit-code mechanism (applied by Execute after defers run),
	// matching dsd health: 2 = any CRIT/unreachable, 1 = any WARN, 0 = clean.
	recordExitCode(summary.ExitCode)
	return nil
}

// buildFleetReport converts fleet.Summary to render.FleetReport. It lives here
// so render/ never needs to import fleet/ — the cmd layer bridges the two packages.
func buildFleetReport(s fleet.Summary) render.FleetReport {
	now := time.Now()
	report := render.FleetReport{
		Date:             now.Format("2006-01-02 15:04:05 MST"),
		Version:          version.Version,
		Verdict:          s.Verdict,
		Total:            s.Total,
		CountOK:          s.Counts.OK,
		CountWarn:        s.Counts.WARN,
		CountCrit:        s.Counts.CRIT,
		CountUnreachable: s.Counts.Unreachable,
		Year:             now.Year(),
	}
	switch s.Verdict {
	case "CRIT":
		report.VerdictClass = "crit"
		report.VerdictText = fmt.Sprintf("%d host(s) have critical issues or are unreachable.", s.Counts.CRIT+s.Counts.Unreachable)
	case "WARN":
		report.VerdictClass = "warn"
		report.VerdictText = fmt.Sprintf("%d host(s) have warnings — review recommended.", s.Counts.WARN)
	default:
		report.VerdictClass = "ok"
		report.VerdictText = "All hosts are healthy."
	}
	for _, h := range s.Hosts {
		row := render.FleetHostRow{
			Host:      h.Host,
			Hostname:  h.Hostname,
			Crit:      h.Crit,
			Warn:      h.Warn,
			ElapsedMs: h.ElapsedMs,
		}
		if !h.Reachable || h.Worst == "ERROR" {
			row.Status, row.StatusClass = "UNREACHABLE", "error"
			row.TopIssue = h.Error
		} else {
			row.Status = h.Worst
			row.StatusClass = strings.ToLower(h.Worst)
			row.TopIssue = h.TopIssue
		}
		report.Hosts = append(report.Hosts, row)
	}
	reachable := s.Total - s.Counts.Unreachable
	for _, g := range s.Issues {
		where := fmt.Sprintf("%d/%d", g.Count, reachable)
		if g.Scope == "outlier" && len(g.Hosts) == 1 {
			where = g.Hosts[0]
		}
		report.Issues = append(report.Issues, render.FleetIssueRow{
			Scope:      g.Scope,
			ScopeClass: strings.ReplaceAll(g.Scope, "-", ""),
			Level:      g.Level,
			LevelClass: strings.ToLower(g.Level),
			Check:      g.Check,
			Where:      where,
			Sample:     truncate(strings.ReplaceAll(g.Sample, "\n", " "), 80),
		})
	}
	report.Consequences = fleetConsequences(s)
	return report
}

func resolveHosts(args []string, hostsFile string) ([]string, error) {
	seen := make(map[string]bool)
	var hosts []string
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" || strings.HasPrefix(h, "#") || seen[h] {
			return
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	for _, a := range args {
		add(a)
	}
	if hostsFile != "" {
		f, err := os.Open(hostsFile)
		if err != nil {
			return nil, fmt.Errorf("reading --hosts-file: %w", err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return hosts, nil
}

func printFleetTable(summary fleet.Summary, mode output.OutputMode) {
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "HOST\tSTATUS\tCRIT\tWARN\tTIME\tTOP ISSUE")
	for _, r := range summary.Hosts {
		status := fleetStatusLabel(r, mode)
		issue := r.TopIssue
		if !r.Reachable {
			issue = r.Error
		}
		issue = truncate(strings.ReplaceAll(issue, "\n", " "), 60)
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%dms\t%s\n",
			r.Host, status, r.Crit, r.Warn, r.ElapsedMs, issue)
	}
	_ = w.Flush()
	c := summary.Counts
	fmt.Printf("\n%d host(s): %d OK · %d WARN · %d CRIT · %d unreachable\n",
		summary.Total, c.OK, c.WARN, c.CRIT, c.Unreachable)
	printFleetIssues(summary, mode)
	if n := fleetWaitlistNudge(mode, summary.Total); n != "" {
		fmt.Println(n)
	}
}

// printFleetIssues renders WARN/CRIT issues grouped across the fleet: fleet-wide
// (systemic — fix once) first, then outliers (one host drifting from the rest).
// This is the fleet's answer to "what's wrong, and is it everywhere or one box?".
func printFleetIssues(summary fleet.Summary, _ output.OutputMode) {
	if len(summary.Issues) == 0 {
		return
	}
	reachable := summary.Total - summary.Counts.Unreachable
	fmt.Println("\nFleet issues (grouped across hosts):")
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "  SCOPE\tLVL\tCHECK\tHOSTS\tISSUE")
	const limit = 15
	shown := 0
	for _, g := range summary.Issues {
		if shown >= limit {
			fmt.Fprintf(w, "  …\t\t\t\t%d more (see --json)\n", len(summary.Issues)-shown)
			break
		}
		where := fmt.Sprintf("%d/%d", g.Count, reachable)
		if g.Scope == "outlier" && len(g.Hosts) == 1 {
			where = g.Hosts[0]
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
			g.Scope, g.Level, g.Check, where,
			truncate(strings.ReplaceAll(g.Sample, "\n", " "), 52))
		shown++
	}
	_ = w.Flush()
}

// fleetWaitlistNudge returns a one-line, suppressible pointer to the (waitlisted)
// hosted Team dashboard. `dsd fleet` itself is and stays free and local (ADR-0004);
// this is NOT a paywall — just a nudge toward the backend-backed product that
// persists/centralises what fleet already shows. Shown only on genuine multi-host
// runs (the team signal), only in this human/table path (never --json), and
// silenced by DSD_NO_NUDGE or the existing DSD_NO_UPDATE_CHECK.
func fleetWaitlistNudge(mode output.OutputMode, hostCount int) string {
	if hostCount < 2 {
		return ""
	}
	if os.Getenv("DSD_NO_NUDGE") != "" || os.Getenv("DSD_NO_UPDATE_CHECK") != "" {
		return ""
	}
	icon := asciiOr("info", "💡", mode)
	return fmt.Sprintf("%s  Team mode — one hosted dashboard for every host, with history & alerts — is on the way.\n   Join the waitlist: https://dashdiag.sh/plans  (silence: DSD_NO_NUDGE=1)", icon)
}

func fleetStatusLabel(r fleet.Result, mode output.OutputMode) string {
	if !r.Reachable || r.Worst == "ERROR" {
		if mode == output.ModeHuman {
			return "🔌 UNREACHABLE"
		}
		return "UNREACHABLE"
	}
	if mode == output.ModeHuman {
		switch r.Worst {
		case "CRIT":
			return "❌ CRIT"
		case "WARN":
			return "⚠️  WARN"
		default:
			return "✅ OK"
		}
	}
	return r.Worst
}
