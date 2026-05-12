package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/spf13/cobra"
)

var storyCmd = &cobra.Command{
	Use:   "story [snapshots]",
	Short: "Narrative incident timeline from captured health snapshots",
	Long: `Render a human-readable timeline of system health over time.

Reads the last N baseline snapshots and narrates incidents,
recoveries, and anomalies as a chronological story.

  dsd story          last 48 snapshots (~24h at 30-min intervals)
  dsd story 96       last 96 snapshots (~48h)
  dsd story 12       last 12 snapshots (~6h)

Snapshots are captured automatically when dsd health runs.
Run 'dsd health' or set up a cron job to build history:

  */30 * * * * /usr/local/bin/dsd health --terse >> /var/log/dsd.log 2>&1`,
	Args: cobra.MaximumNArgs(1),
	RunE: runStory,
}

func init() {
	rootCmd.AddCommand(storyCmd)
	storyCmd.Flags().Bool("plain", false, "plain text output (no colour)")
}

func runStory(cmd *cobra.Command, args []string) error {
	n := 48
	if len(args) == 1 {
		v, err := strconv.Atoi(args[0])
		if err != nil || v < 2 {
			fmt.Fprintf(os.Stderr, "dsd: story: snapshots must be an integer ≥ 2, got %q\n", args[0])
			return fmt.Errorf("invalid snapshot count")
		}
		n = v
	}

	history, err := baseline.LoadHistory(n)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsd: story: cannot load history: %v\n", err)
		return err
	}
	if len(history) < 2 {
		fmt.Fprintln(os.Stderr, "dsd: story: not enough history yet — run 'dsd health' a few times to build a timeline")
		fmt.Fprintln(os.Stderr, "    tip: set up a cron job: */30 * * * * dsd health --terse")
		os.Exit(1)
	}

	out := render.RenderStoryFromHistory(history)
	fmt.Println(out)
	return nil
}
