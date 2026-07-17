package cmd

// diff.go — `dsd diff <baseline.tar.gz> <current.tar.gz>` and `dsd diff --last`
//
// Two modes:
//   - Bundle diff (2 args): compare two raw capture bundles offline. A discoverable
//     alias for `dsd replay <current> --diff <baseline>`. Arg order is "old new".
//   - Store diff (--last): compare the last two persisted health runs from the local
//     store, showing which check statuses changed between them.
//
// This is the support workflow front door (ADR-0003) and the quick "what changed
// since my last dsd health --persist run?" shortcut.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/store"
)

var diffCmd = &cobra.Command{
	Use:   "diff [<baseline.tar.gz> <current.tar.gz>]",
	Short: "Diff two capture bundles — show what changed between them (offline)",
	Long: `Compare two raw capture bundles (from dsd capture --raw) of the same host
and print only what changed. Argument order is "old new" like diff/git diff:
the first bundle is the baseline, the second is the current state.

  dsd diff healthy.tar.gz broke.tar.gz          # human change report
  dsd diff healthy.tar.gz broke.tar.gz --json   # machine-readable diff

Or use --last to diff the two most recent persisted health runs:

  dsd diff --last                               # what changed since last persist
  dsd diff --last --json                        # machine-readable store diff

This is the same engine as 'dsd replay <current> --diff <baseline>', with the
more intuitive two-argument form.

NOTE: bundle diff runs inside a linux binary to exercise linux-specific parsers;
the bundles are portable but the binary is not (use an OrbStack container on macOS).`,
	Args:             cobra.RangeArgs(0, 2),
	PersistentPreRun: func(_ *cobra.Command, _ []string) { /* suppress brand header */ },
	RunE:             runDiff,
}

func init() {
	rootCmd.AddCommand(diffCmd)
	diffCmd.Flags().Bool("json", false, "machine-readable diff output")
	diffCmd.Flags().Bool("gpu", false, "include GPU collector")
	diffCmd.Flags().Bool("pkg", false, "include package collector")
	diffCmd.Flags().Bool("deep", false, "include deep collectors")
	diffCmd.Flags().Bool("cve", false, "include the CVE collector (both bundles must be captured with capture --raw --cve-scan)")
	diffCmd.Flags().Bool("force", false, "diff even when a bundle's OS differs from this machine (output will NOT be faithful)")
	diffCmd.Flags().Bool("last", false, "diff the last two persisted health runs from the local store")
	diffCmd.Flags().String("host", "", "hostname filter for --last (defaults to this machine's hostname)")
}

func runDiff(cmd *cobra.Command, args []string) error {
	last, _ := cmd.Flags().GetBool("last")
	if last {
		return runDiffFromStore(cmd)
	}
	if len(args) != 2 {
		return fmt.Errorf("dsd diff requires 2 bundle paths, or use --last to diff from the store")
	}
	base, err := loadBundle(args[0])
	if err != nil {
		return fmt.Errorf("loading baseline bundle: %w", err)
	}
	current, err := loadBundle(args[1])
	if err != nil {
		return fmt.Errorf("loading current bundle: %w", err)
	}

	jsonOut, _ := cmd.Flags().GetBool("json")
	gpu, _ := cmd.Flags().GetBool("gpu")
	pkg, _ := cmd.Flags().GetBool("pkg")
	deep, _ := cmd.Flags().GetBool("deep")
	cve, _ := cmd.Flags().GetBool("cve")
	force, _ := cmd.Flags().GetBool("force")

	return renderCaptureDiff(base, current, deep, pkg, gpu, cve, jsonOut, force)
}

func runDiffFromStore(cmd *cobra.Command) error {
	host, _ := cmd.Flags().GetString("host")
	if host == "" {
		h, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("resolving hostname: %w", err)
		}
		host = h
	}

	entries, err := store.ReadAll(store.StorePath(), host, 2)
	if err != nil {
		return fmt.Errorf("reading store: %w", err)
	}
	if len(entries) < 2 {
		return fmt.Errorf("need at least 2 stored runs for --last (have %d for %q); run 'dsd health --persist' to build history", len(entries), host)
	}

	prev, cur := entries[len(entries)-2], entries[len(entries)-1]
	changes := store.DiffChecks(prev, cur)

	jsonOut, _ := cmd.Flags().GetBool("json")
	return renderStoreDiff(prev, cur, changes, jsonOut)
}

type storeDiffOutput struct {
	Before  store.Entry        `json:"before"`
	After   store.Entry        `json:"after"`
	Changes []store.CheckChange `json:"changes"`
}

func renderStoreDiff(prev, cur store.Entry, changes []store.CheckChange, jsonOut bool) error {
	// Sort by severity of the "after" status so regressions surface first.
	sort.Slice(changes, func(i, j int) bool {
		ri, rj := statusRank(changes[i].After), statusRank(changes[j].After)
		if ri != rj {
			return ri > rj
		}
		return changes[i].Name < changes[j].Name
	})

	if jsonOut {
		data, err := json.MarshalIndent(storeDiffOutput{Before: prev, After: cur, Changes: changes}, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding diff: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	ago := cur.Timestamp.Sub(prev.Timestamp).Round(time.Minute)
	fmt.Printf("before: %s  verdict=%s\n", prev.Timestamp.Local().Format("2006-01-02 15:04"), prev.Verdict)
	fmt.Printf("after:  %s  verdict=%s  (%s later)\n\n", cur.Timestamp.Local().Format("2006-01-02 15:04"), cur.Verdict, ago)

	if len(changes) == 0 {
		fmt.Println("no check status changes between these two runs")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "CHECK\tBEFORE\tAFTER")
	for _, c := range changes {
		before := c.Before
		if before == "" {
			before = "(new)"
		}
		after := c.After
		if after == "" {
			after = "(gone)"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", c.Name, before, after)
	}
	_ = w.Flush()
	return nil
}

// statusRank returns a numeric rank for check statuses: CRIT > WARN > OK > INFO > others > gone.
// Used to sort store-diff changes so regressions (new CRIT/WARN) appear first.
func statusRank(status string) int {
	switch status {
	case "CRIT":
		return 4
	case "WARN":
		return 3
	case "OK":
		return 2
	case "INFO":
		return 1
	case "":
		return -1 // (gone) — least urgent
	default:
		return 0
	}
}
