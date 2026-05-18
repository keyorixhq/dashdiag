package cmd

import (
	"fmt"
	"os"

	"github.com/keyorixhq/dashdiag/internal/platform"
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
			fmt.Fprintf(os.Stderr, "⚡ DashDiag (dsd) %s — %s\n", version.Version, platform.SystemLabel())
		}
	},
	RunE: runHealth,
	Version: fmt.Sprintf("%s (commit %s, built %s)",
		version.Version, version.Commit, version.Built),
}

// TODO(backlog): --share flag — upload snapshot to dashdiag.sh, return shareable URL.
// Viral: every shared link is a product impression. Requires dashdiag.sh backend.
// Estimated scope: ~1 day CLI side + backend. See BACKLOG.md.

// TODO(backlog): --badge flag — shields.io-compatible badge showing system health status.
// Embeds in GitHub README. Viral — visible to every repo visitor.
// Requires dashdiag.sh backend. Estimated scope: ~2 hours CLI + backend. See BACKLOG.md.

// TODO(backlog): team workspace MVP — shared snapshot history across a team.
// First paid product. Requires dashdiag.sh backend, auth, billing.
// Design session required before implementation. See BACKLOG.md §Strategic Discussions.
// Estimated scope: ~10 days.

func init() {
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
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
