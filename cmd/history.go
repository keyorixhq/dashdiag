package cmd

// history.go — `dsd history`
//
// Shows the last N health run verdicts recorded by `dsd health --persist`,
// with per-run change indicators so you can see at a glance when and how the
// host's health changed over time.
//
// Typical workflow:
//   crontab: */30 * * * * /usr/local/bin/dsd health --persist >/dev/null
//   on demand: dsd history --n 48   # last 24 h at 30-min cadence

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/store"
)

func init() {
	rootCmd.AddCommand(historyCmd)
	historyCmd.Flags().IntP("n", "n", 20, "number of past runs to show (most recent N)")
	historyCmd.Flags().String("host", "", "hostname to query (default: this machine)")
	historyCmd.Flags().Bool("json", false, "machine-readable output")
}

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Show recent health-run history from the local state store",
	Long: `Display the last N health verdicts recorded by 'dsd health --persist'.
Each row shows the run timestamp, overall verdict, and which check statuses
changed since the previous run — so you can see at a glance when the host's
health changed and exactly what flipped.

Enable persistent recording once:

  echo '*/30 * * * * /usr/local/bin/dsd health --persist >/dev/null' | crontab -

Then inspect the trend:

  dsd history            # last 20 runs
  dsd history --n 48     # last 48 runs (~24 h at 30-min cadence)
  dsd history --json     # machine-readable (for dashboards / scripts)

The store lives at ~/.dsd/store.jsonl (non-root) or
/var/lib/dashdiag/store.jsonl (root).`,
	RunE: runHistory,
}

// historyRow is one rendered row, used for both tabwriter and JSON output.
type historyRow struct {
	Timestamp string              `json:"ts"`
	Verdict   string              `json:"verdict"`
	Changes   []store.CheckChange `json:"changes"`
}

func runHistory(cmd *cobra.Command, _ []string) error {
	n, _ := cmd.Flags().GetInt("n")
	host, _ := cmd.Flags().GetString("host")
	jsonOut, _ := cmd.Flags().GetBool("json")

	if host == "" {
		h, err := os.Hostname()
		if err == nil {
			host = h
		}
	}

	path := store.StorePath()
	entries, err := store.ReadAll(path, host, n)
	if err != nil {
		return fmt.Errorf("history: %w", err)
	}
	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "no history yet for %s — run 'dsd health --persist' to start recording\n", host)
		return nil
	}

	rows := buildHistoryRows(entries)

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}

	printHistoryTable(rows, host)
	return nil
}

func buildHistoryRows(entries []store.Entry) []historyRow {
	rows := make([]historyRow, len(entries))
	for i, e := range entries {
		var changes []store.CheckChange
		if i > 0 {
			changes = store.DiffChecks(entries[i-1], e) //nolint:gosec // i>0 guard above ensures i-1 is valid
		}
		rows[i] = historyRow{
			Timestamp: e.Timestamp.Local().Format("2006-01-02 15:04:05"),
			Verdict:   e.Verdict,
			Changes:   changes,
		}
	}
	return rows
}

func printHistoryTable(rows []historyRow, host string) {
	fmt.Printf("Health history for %s  (%d run(s))\n\n", host, len(rows))
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tVERDICT\tCHANGES")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\n", r.Timestamp, r.Verdict, formatChanges(r.Changes))
	}
	_ = w.Flush()
}

// formatChanges renders changes as a compact inline string, e.g.
// "memory OK→WARN · disk WARN→CRIT · +2 more" or "—" when nothing changed.
func formatChanges(changes []store.CheckChange) string {
	if len(changes) == 0 {
		return "—"
	}
	const show = 4
	parts := make([]string, 0, show)
	for i, c := range changes {
		if i >= show {
			break
		}
		before, after := c.Before, c.After
		if before == "" {
			before = "new"
		}
		if after == "" {
			after = "gone"
		}
		parts = append(parts, c.Name+" "+before+"→"+after)
	}
	out := strings.Join(parts, " · ")
	if len(changes) > show {
		out += fmt.Sprintf(" · +%d more", len(changes)-show)
	}
	return out
}
