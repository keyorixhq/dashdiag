package cmd

import (
	"fmt"
	"os"

	"github.com/andreibeshkov/dashdiag/internal/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "dsd",
	Short: "DashDiag — instant system health",
	RunE:  runHealth,
	Version: fmt.Sprintf("%s (commit %s, built %s)",
		version.Version, version.Commit, version.Built),
}

func init() {
	rootCmd.SuggestionsMinimumDistance = 2

	f := rootCmd.PersistentFlags()
	f.Bool("plain", false, "plain text output")
	f.Bool("json", false, "JSON output")
	f.Bool("yaml", false, "YAML output")
	f.Bool("report", false, "generate full report")
	f.String("out", "", "write output to file")
	f.Bool("debug", false, "enable debug logging")
	f.Bool("compact", false, "compact output")
	f.Bool("diff", false, "show diff from previous run")
	f.Bool("since-deploy", false, "show metrics since last deploy")
	f.Bool("watch", false, "watch mode — refresh periodically")
	f.String("post-mortem", "", "generate post-mortem for given incident ID")
	f.Bool("share", false, "share report via URL")
	f.Bool("qr", false, "display share URL as QR code")
}

func runHealth(cmd *cobra.Command, args []string) error {
	fmt.Fprintln(os.Stdout, "dsd health — not yet implemented")
	return nil
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
