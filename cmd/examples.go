package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(examplesCmd)
	examplesCmd.Flags().Int("scenario", 0, "show one scenario (1-9)")
}

var examplesCmd = &cobra.Command{
	Use:   "examples",
	Short: "Real-world usage workflows",
	RunE:  runExamples,
}

func runExamples(cmd *cobra.Command, _ []string) error {
	n, _ := cmd.Flags().GetInt("scenario")
	scenarios := []struct{ title, desc, commands string }{
		{
			"1. Incident triage",
			"Something is wrong. Find out what changed and document it.",
			"  dsd health\n  dsd health --diff\n  dsd health --story\n  dsd health --post-mortem \"API latency spike\"",
		},
		{
			"2. Pre-deploy check",
			"Verify system is healthy before pushing to production.",
			"  dsd health\n  dsd health deep",
		},
		{
			"3. Network investigation",
			"Connectivity issues or high latency.",
			"  dsd net\n  dsd net deep",
		},
		{
			"4. Share with team",
			"Share a snapshot in Slack without requiring install.",
			"  dsd health --share\n  dsd health --report --out report.md",
		},
		{
			"5. Kubernetes cluster",
			"Check pod health, OOM kills, and node conditions.",
			"  dsd k8s\n  dsd k8s deep",
		},
		{
			"6. Automate health checks",
			"Run dsd on SSH login, git push, or in CI pipelines.",
			"  dsd hook install",
		},
		{
			"7. Understand a finding",
			"health flagged a subsystem — learn what it means and how to fix it.",
			"  dsd explain swap\n  dsd explain zfs\n  dsd health --explain",
		},
		{
			"8. Monitoring integration",
			"Wire dsd into Nagios/Icinga or Prometheus — exit codes already match.",
			"  dsd health --nagios\n  dsd health --prometheus > /var/lib/node_exporter/textfile_collector/dsd.prom",
		},
		{
			"9. Watch an incident unfold",
			"Refresh on an interval and see only what changed since the last tick.",
			"  dsd health --watch\n  dsd health --watch --watch-interval 5s",
		},
	}
	for i, s := range scenarios {
		if n != 0 && n != i+1 {
			continue
		}
		fmt.Printf("\n%s\n%s\n%s\n", s.title, s.desc, s.commands)
	}
	return nil
}
