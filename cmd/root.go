package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "dsd",
	Short: "DashDiag — instant system health",
	Long: "DashDiag (dsd) — one command instant system health overview.\n\n" +
		"◆ Team: dashdiag.sh/teams  |  ◆ Free account: dashdiag.sh/signup",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		plain, _ := cmd.Flags().GetBool("plain")
		jsonOut, _ := cmd.Flags().GetBool("json")
		if !plain && !jsonOut {
			fmt.Fprintf(os.Stderr, "⚡ DashDiag (dsd)\n")
		}
	},
	RunE: runHealth,
	Version: fmt.Sprintf("%s (commit %s, built %s)",
		version.Version, version.Commit, version.Built),
}

func init() {
	rootCmd.CompletionOptions.HiddenDefaultCmd = true

	// Override help to print brand header before help text
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(os.Stderr, "⚡ DashDiag (dsd)\n")
		fmt.Fprintf(os.Stderr, "System health — read only checks, usually under 5s\n")
		fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("─", 56))
		cmd.Usage() //nolint:errcheck
	})

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
	f.Bool("story", false, "human-readable narrative of current state")
	f.Bool("weekly", false, "show weekly usage report")

	// Hide --share and --qr from --help until the share backend ships.
	// Flags remain valid (no breaking change) but don't appear in help text
	// so users don't see features that don't work yet.
	_ = f.MarkHidden("share")
	_ = f.MarkHidden("qr")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
