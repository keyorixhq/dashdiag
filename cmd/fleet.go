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
  dsd fleet --json web1 web2 | jq .

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
	results := fleet.Run(cmd.Context(), hosts, opts)

	if jsonOut {
		data, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(data))
	} else {
		printFleetTable(results, mode)
	}

	// Use the shared exit-code mechanism (applied by Execute after defers run),
	// matching dsd health: 2 = any CRIT/unreachable, 1 = any WARN, 0 = clean.
	recordExitCode(fleet.WorstExitCode(results))
	return nil
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

func printFleetTable(results []fleet.Result, mode output.OutputMode) {
	results = fleet.SortByHost(results)
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "HOST\tSTATUS\tCRIT\tWARN\tTIME\tTOP ISSUE")
	var ok, warn, crit, unreachable int
	for _, r := range results {
		status := fleetStatusLabel(r, mode)
		issue := r.TopIssue
		if !r.Reachable {
			issue = r.Error
		}
		issue = truncate(strings.ReplaceAll(issue, "\n", " "), 60)
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%dms\t%s\n",
			r.Host, status, r.Crit, r.Warn, r.ElapsedMs, issue)
		switch {
		case !r.Reachable || r.Worst == "ERROR":
			unreachable++
		case r.Worst == "CRIT":
			crit++
		case r.Worst == "WARN":
			warn++
		default:
			ok++
		}
	}
	_ = w.Flush()
	fmt.Printf("\n%d host(s): %d OK · %d WARN · %d CRIT · %d unreachable\n",
		len(results), ok, warn, crit, unreachable)
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
