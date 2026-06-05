package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/selfupdate"
	"github.com/keyorixhq/dashdiag/internal/version"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update dsd to the latest release",
	Long: `Check the GitHub releases for a newer dsd, and (with confirmation) download,
checksum-verify, and replace this binary in place.

The download is sha256-verified against the release's checksums.txt before the
running binary is atomically replaced. If the binary lives somewhere only root
can write (e.g. /usr/local/bin), re-run with sudo.

Examples:
  dsd update            check, then prompt to install if newer
  dsd update --check    report only — do not install
  dsd update --yes      install without prompting`,
	RunE: runUpdate,
}

func init() {
	rootCmd.AddCommand(updateCmd)
	updateCmd.Flags().Bool("check", false, "only report whether an update is available")
	updateCmd.Flags().BoolP("yes", "y", false, "install without prompting")
}

func runUpdate(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
	defer cancel()

	current := version.Version
	rel, err := selfupdate.LatestRelease(ctx)
	if err != nil {
		return fmt.Errorf("checking for updates: %w", err)
	}

	isDev := !strings.HasPrefix(current, "v") || current == "dev"
	switch {
	case isDev:
		fmt.Printf("Running a dev build (%s). Latest release is %s.\n", current, rel.TagName)
	case selfupdate.IsNewer(current, rel.TagName):
		fmt.Printf("Update available: %s → %s\n  %s\n", current, rel.TagName, rel.HTMLURL)
	default:
		fmt.Printf("dsd %s is already the latest release.\n", current)
		// Keep the nudge cache fresh so other commands don't re-check.
		_, _ = selfupdate.RefreshCache(ctx)
		return nil
	}

	checkOnly, _ := cmd.Flags().GetBool("check")
	if checkOnly {
		_, _ = selfupdate.RefreshCache(ctx)
		return nil
	}

	yes, _ := cmd.Flags().GetBool("yes")
	if !yes && !confirm(fmt.Sprintf("Install %s now?", rel.TagName)) {
		fmt.Println("Aborted.")
		return nil
	}

	fmt.Printf("Downloading %s…\n", selfupdate.AssetName())
	path, err := selfupdate.Apply(ctx, rel)
	if err != nil {
		return err
	}
	fmt.Printf("✅ Updated to %s (%s). Re-run dsd to use the new version.\n", rel.TagName, path)
	return nil
}

func confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
