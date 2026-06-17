package cmd

// sanitize.go — `dsd sanitize <bundle.tar.gz>`
//
// Best-effort credential redaction for an ALREADY-captured raw bundle, writing a
// new sanitized bundle. The capture-time path is `dsd capture --raw --sanitize`;
// this is for the "already captured (or someone handed me a bundle) and I want to
// scrub it before sharing" case. Same engine: source.Bundle.Sanitize(). See ADR-0003.

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var sanitizeCmd = &cobra.Command{
	Use:   "sanitize <bundle.tar.gz>",
	Short: "Redact secrets from an existing capture bundle (best-effort), for safe sharing",
	Long: `Redact common credentials from an already-captured raw bundle and write a
sanitized copy, so it can be shared for offline 'dsd replay' / 'dsd diff' without
leaking secrets. Use this when a bundle was captured without --sanitize (or was
handed to you by someone else); to sanitize at capture time, use
'dsd capture --raw --sanitize'.

Redacts (best-effort): PEM private keys, password/secret/token/api_key/access_key
assignments, AWS access key IDs, HTTP bearer tokens, and /etc/shadow hashes — in
recorded files and command output. Redaction is deterministic, so the sanitized
bundle still replays to the same verdicts. Identifiers (hostname, IPs, serials) are
NOT redacted (kept for replay fidelity).

  dsd sanitize dsd-raw-host.tar.gz                  # writes dsd-raw-host-sanitized.tar.gz
  dsd sanitize dsd-raw-host.tar.gz -o clean.tar.gz

NOTE: best-effort only — REVIEW a bundle before sharing it.`,
	Args:             cobra.ExactArgs(1),
	PersistentPreRun: func(_ *cobra.Command, _ []string) {},
	RunE:             runSanitize,
}

func init() {
	rootCmd.AddCommand(sanitizeCmd)
	sanitizeCmd.Flags().StringP("out", "o", "",
		"output path (default: <input> with a -sanitized suffix)")
}

func runSanitize(cmd *cobra.Command, args []string) error {
	in := args[0]
	b, err := loadBundle(in)
	if err != nil {
		return fmt.Errorf("loading bundle: %w", err)
	}

	rep := b.Sanitize()

	out, _ := cmd.Flags().GetString("out")
	if out == "" {
		out = sanitizedOutPath(in)
	}
	if err := b.SaveTarball(out); err != nil {
		return fmt.Errorf("writing sanitized bundle: %w", err)
	}

	fmt.Fprintf(os.Stderr, "✅ Sanitized bundle written: %s\n", out)
	fmt.Fprintf(os.Stderr, "   %d redaction(s) across %d file(s) + %d command(s).\n",
		rep.TotalRedactions, rep.FilesRedacted, rep.CommandsRedacted)
	fmt.Fprintln(os.Stderr, "   NOTE: best-effort credential redaction only — REVIEW before sharing.")
	fmt.Fprintln(os.Stderr, "   Identifiers (hostname, IPs, disk serials) are NOT redacted (kept for replay).")
	return nil
}

// sanitizedOutPath turns "foo.tar.gz" into "foo-sanitized.tar.gz" (and handles a
// plain "foo" → "foo-sanitized").
func sanitizedOutPath(in string) string {
	for _, ext := range []string{".tar.gz", ".tgz", ".tar"} {
		if strings.HasSuffix(in, ext) {
			return strings.TrimSuffix(in, ext) + "-sanitized" + ext
		}
	}
	return in + "-sanitized"
}
