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
		outPath, _ := cmd.Flags().GetString("out")
		if !plain && !jsonOut && outPath == "" {
			fmt.Fprintf(os.Stderr, "⚡ DashDiag (dsd) %s — %s\n", version.Version, platform.SystemLabel())
		}
		// --out: redirect stdout to file for any command
		if outPath != "" {
			f, err := os.Create(outPath) // #nosec G304
			if err != nil {
				fmt.Fprintf(os.Stderr, "dsd: --out: %v\n", err)
				os.Exit(1)
			}
			// intentionally not closing f — process exits after command completes
			os.Stdout = f
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
	f.Bool("plain", false, "plain text output (no colour, machine-friendly)")
	f.Bool("json", false, "JSON output (machine-readable)")
	f.String("out", "", "write output to file")
	f.Bool("watch", false, "watch mode — refresh periodically")
	f.Bool("share", false, "share report via URL")
	f.Bool("qr", false, "display share URL as QR code")

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
	// Apply the worst-severity exit code recorded by standalone subcommands
	// (BUG-022). Done after Execute() returns so command defers (progress
	// cleanup, --out file) have already run. health/tls exit directly and never
	// reach here; for everything else pendingExitCode is 0 unless severity was
	// recorded, so this is a no-op for clean runs.
	if pendingExitCode != 0 {
		os.Exit(pendingExitCode)
	}
}
