package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// compareSnapshot is the minimal subset of dsd health --json we need.
type compareSnapshot struct {
	Hostname  string           `json:"hostname"`
	Timestamp string           `json:"timestamp"`
	Version   string           `json:"version"`
	Checks    []compareCheck   `json:"checks"`
	Insights  []compareInsight `json:"insights"`
}

type compareCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type compareInsight struct {
	Level   string `json:"level"`
	Check   string `json:"check"`
	Message string `json:"message"`
}

var compareCmd = &cobra.Command{
	Use:   "compare [file1.json] [file2.json] ...",
	Short: "Compare health snapshots across multiple hosts",
	Long: `Compare dsd health --json snapshots from multiple hosts.

Reads snapshots from files or stdin and shows:
  - Which checks differ between hosts
  - Which host looks like an outlier
  - Per-check status matrix across all hosts

Collect snapshots then compare:

  # Capture from multiple hosts
  ssh web1 dsd health --json > web1.json
  ssh web2 dsd health --json > web2.json
  ssh web3 dsd health --json > web3.json
  dsd compare web1.json web2.json web3.json

  # Or pipe directly
  dsd health --json | ssh web2 'cat - <(dsd health --json)' | dsd compare

  # Compare against a golden baseline
  dsd health --json > golden.json
  # ... later ...
  dsd health --json | dsd compare golden.json -`,
	Args: cobra.MinimumNArgs(0),
	RunE: runCompare,
}

func init() {
	rootCmd.AddCommand(compareCmd)
	compareCmd.Flags().Bool("plain", false, "plain text output")
	compareCmd.Flags().Bool("all", false, "show all checks, not just differing ones")
}

func runCompare(cmd *cobra.Command, args []string) error {
	plain, _ := cmd.Flags().GetBool("plain")
	showAll, _ := cmd.Flags().GetBool("all")

	snapshots, err := loadCompareSnapshots(args)
	if err != nil {
		return err
	}
	if len(snapshots) < 2 {
		fmt.Fprintln(os.Stderr, "dsd: compare: need at least 2 snapshots to compare")
		fmt.Fprintln(os.Stderr, "    usage: dsd compare host1.json host2.json ...")
		os.Exit(1)
	}

	printCompare(snapshots, plain, showAll)
	return nil
}

// loadCompareSnapshots reads JSON snapshots from files and/or stdin ("-").
func loadCompareSnapshots(args []string) ([]*compareSnapshot, error) {
	var snapshots []*compareSnapshot

	// No args — read from stdin
	if len(args) == 0 {
		snaps, err := readCompareStream(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		return snaps, nil
	}

	for _, arg := range args {
		if arg == "-" {
			snaps, err := readCompareStream(os.Stdin)
			if err != nil {
				return nil, fmt.Errorf("reading stdin: %w", err)
			}
			snapshots = append(snapshots, snaps...)
			continue
		}
		f, err := os.Open(arg) // #nosec G304 -- user-provided path
		if err != nil {
			return nil, fmt.Errorf("cannot open %q: %w", arg, err)
		}
		snaps, err := readCompareStream(f)
		f.Close() //nolint:errcheck
		if err != nil {
			return nil, fmt.Errorf("cannot parse %q: %w", arg, err)
		}
		snapshots = append(snapshots, snaps...)
	}
	return snapshots, nil
}

// readCompareStream reads one or more newline-delimited JSON objects from r.
// Supports both single JSON objects and concatenated/streamed JSON.
func readCompareStream(r io.Reader) ([]*compareSnapshot, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	// Try as a single JSON object first
	var single compareSnapshot
	if err := json.Unmarshal(data, &single); err == nil {
		return []*compareSnapshot{&single}, nil
	}
	// Try as newline-delimited JSON
	var out []*compareSnapshot
	dec := json.NewDecoder(strings.NewReader(string(data)))
	for dec.More() {
		var s compareSnapshot
		if err := dec.Decode(&s); err != nil {
			return nil, err
		}
		out = append(out, &s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid JSON snapshots found")
	}
	return out, nil
}

// printCompare renders the comparison matrix.
func printCompare(snaps []*compareSnapshot, plain, showAll bool) {
	sep := strings.Repeat("─", 60)

	// Header
	fmt.Printf("\n%s\n", sep)
	fmt.Printf("Fleet comparison — %d hosts\n", len(snaps))
	fmt.Printf("%s\n\n", sep)

	// Host list with timestamp
	for i, s := range snaps {
		ts := s.Timestamp
		if len(ts) > 19 {
			ts = ts[:19]
		}
		fmt.Printf("  [%d] %s  (%s)\n", i+1, s.Hostname, ts)
	}
	fmt.Println()

	// Build check index: checkName → []status (one per host)
	allChecks := collectCheckNames(snaps)
	statusMatrix := buildStatusMatrix(snaps, allChecks)

	// Classify checks
	type row struct {
		name     string
		statuses []string
		differs  bool
	}
	var rows []row
	for _, name := range allChecks {
		statuses := statusMatrix[name]
		differs := statusesDiffer(statuses)
		rows = append(rows, row{name, statuses, differs})
	}

	// Count diverging checks
	diverging := 0
	for _, r := range rows {
		if r.differs {
			diverging++
		}
	}

	if diverging == 0 {
		fmt.Println("✅  All checks identical across all hosts")
	} else {
		fmt.Printf("⚠️   %d check(s) differ across hosts\n\n", diverging)
	}

	// Print matrix
	fmt.Printf("%-20s", "CHECK")
	for i, s := range snaps {
		label := s.Hostname
		if len(label) > 12 {
			label = label[:12]
		}
		fmt.Printf("  %-12s", fmt.Sprintf("[%d]%s", i+1, label))
	}
	fmt.Println()
	fmt.Println(strings.Repeat("─", 20+len(snaps)*14))

	for _, r := range rows {
		if !showAll && !r.differs {
			continue
		}
		marker := "  "
		if r.differs {
			marker = "← "
		}
		fmt.Printf("%s%-18s", marker, r.name)
		for _, s := range r.statuses {
			styled := statusSymbol(s, plain)
			fmt.Printf("  %-12s", styled)
		}
		fmt.Println()
	}

	if !showAll && diverging == 0 {
		fmt.Printf("\n(use --all to show all %d checks)\n", len(allChecks))
	} else if !showAll {
		fmt.Printf("\n(showing %d diverging checks — use --all to see all %d)\n", diverging, len(allChecks))
	}

	// Outlier detection — which host has the most unique bad statuses
	printOutlierAnalysis(snaps, statusMatrix, allChecks, plain)
}

func collectCheckNames(snaps []*compareSnapshot) []string {
	seen := make(map[string]bool)
	var names []string
	for _, s := range snaps {
		for _, c := range s.Checks {
			if !seen[c.Name] {
				seen[c.Name] = true
				names = append(names, c.Name)
			}
		}
	}
	sort.Strings(names)
	return names
}

func buildStatusMatrix(snaps []*compareSnapshot, checks []string) map[string][]string {
	m := make(map[string][]string, len(checks))
	for _, name := range checks {
		statuses := make([]string, len(snaps))
		for i, s := range snaps {
			statuses[i] = "—" // not present on this host
			for _, c := range s.Checks {
				if c.Name == name {
					statuses[i] = c.Status
					break
				}
			}
		}
		m[name] = statuses
	}
	return m
}

func statusesDiffer(statuses []string) bool {
	if len(statuses) == 0 {
		return false
	}
	first := statuses[0]
	for _, s := range statuses[1:] {
		if s != first {
			return true
		}
	}
	return false
}

func statusSymbol(status string, plain bool) string {
	if plain {
		return status
	}
	switch status {
	case "OK":
		return "✅ OK"
	case "WARN":
		return "⚠️  WARN"
	case "CRIT":
		return "❌ CRIT"
	case "INFO":
		return "ℹ️  INFO"
	default:
		return status
	}
}

// printOutlierAnalysis finds the host that diverges most from the majority.
func printOutlierAnalysis(snaps []*compareSnapshot, matrix map[string][]string, checks []string, _ bool) {
	if len(snaps) < 3 {
		return // outlier detection needs at least 3 hosts
	}

	// Score each host: how many checks does it have a unique status for?
	scores := make([]int, len(snaps))
	for _, name := range checks {
		statuses := matrix[name]
		// Count frequency of each status
		freq := make(map[string]int)
		for _, s := range statuses {
			freq[s]++
		}
		// If a host has a status no other host has, it's an outlier for this check
		for i, s := range statuses {
			if freq[s] == 1 {
				scores[i]++
			}
		}
	}

	maxScore := 0
	outlierIdx := -1
	for i, score := range scores {
		if score > maxScore {
			maxScore = score
			outlierIdx = i
		}
	}

	if outlierIdx >= 0 && maxScore > 0 {
		fmt.Printf("\n⚠️   Outlier: [%d] %s differs on %d check(s)\n",
			outlierIdx+1, snaps[outlierIdx].Hostname, maxScore)
	}
}
