package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "dsd",
	Short: "DashDiag — instant system health",
	Long: "DashDiag (dsd) — instant Linux system health in one command.\n\n" +
		"Quick start:\n" +
		"  dsd health     full system check — CPU, memory, disk, network, services… (~5s)\n" +
		"  dsd            same as 'dsd health'\n" +
		"  dsd <area>     focus one area, e.g. dsd disk, dsd net, dsd security, dsd docker\n\n" +
		"◆ Team: dashdiag.sh/teams  |  ◆ Free account: dashdiag.sh/signup",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		applyBrand(cmd)
		applyNetworkPolicy(cmd)
		plain, _ := cmd.Flags().GetBool("plain")
		jsonOut, _ := cmd.Flags().GetBool("json")
		outPath, _ := cmd.Flags().GetString("out")
		if !plain && !jsonOut && outPath == "" {
			fmt.Fprintf(os.Stderr, "⚡ DashDiag (dsd) %s — %s\n", version.Version, platform.SystemLabel())
		}
		// --out: redirect stdout to file for any command
		if outPath != "" {
			f, err := createOutFile(outPath)
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

// createOutFile opens outPath for --out's stdout redirect, refusing to follow
// an existing symlink there. os.Create alone follows symlinks: if dsd runs
// privileged (root, or a service account) and an attacker pre-creates a
// symlink at a predictable/shared --out path pointing at a file they don't
// own (e.g. a config file, another user's data), a plain os.Create would
// silently truncate and overwrite the SYMLINK'S TARGET, not the symlink
// itself. syscall.O_NOFOLLOW makes the open() itself refuse a symlink
// atomically (no separate Lstat-then-open TOCTOU window) while still letting
// a re-run overwrite dsd's own prior REGULAR-file output at the same path —
// the common case.
//
// Mode 0o600 (owner-only) rather than 0o644: --out captures a full diagnostic
// report — SUID paths, process listings, anything that survived redaction —
// and defaults to owner-only rather than world-readable (cmd-11-08). No
// documented dsd workflow reads --out output as a different user.
func createOutFile(outPath string) (*os.File, error) {
	f, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- outPath is a user-supplied CLI flag by design; O_NOFOLLOW blocks symlink-follow
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("refusing to write through a symlink at %q", outPath)
	}
	return f, err
}

// Backlog: --share flag — upload snapshot to dashdiag.sh, return shareable URL.
// Viral: every shared link is a product impression. Requires dashdiag.sh backend.
// Estimated scope: ~1 day CLI side + backend.

// Backlog: --badge flag — shields.io-compatible badge showing system health status.
// Embeds in GitHub README. Viral — visible to every repo visitor.
// Requires dashdiag.sh backend. Estimated scope: ~2 hours CLI + backend.

// Backlog: team workspace MVP — shared snapshot history across a team.
// First paid product. Requires dashdiag.sh backend, auth, billing.
// Design session required before implementation.
// Estimated scope: ~10 days.

// applyBrand reads the --brand/--logo persistent flags and sets the HTML-report brand.
// Called from the root PersistentPreRun (covers every command that inherits it); a
// command that blanks PersistentPreRun (e.g. replay) calls this itself. The render
// package also falls back to DSD_BRAND_* env vars, so a report is branded whether the
// operator passed a flag or exported the env.
func applyBrand(cmd *cobra.Command) {
	company, _ := cmd.Flags().GetString("brand")
	logo, _ := cmd.Flags().GetString("logo")
	if company != "" || logo != "" {
		render.SetBrand(render.Brand{Company: company, Logo: logo})
	}
}

// applyNetworkPolicy reads the --network persistent flag and, if passed, sets
// DSD_ALLOW_NETWORK so every outbound-call site (they each just check
// platform.NetworkAllowed(), a pure env-var read — see internal/platform/
// network_policy.go for why: those call sites span packages, e.g. cvedata
// and drilldown, that a cobra/pflag dependency would be architecturally out
// of place in) sees the same opt-in a script exporting DSD_ALLOW_NETWORK
// directly would produce. DSD_OFFLINE, if already set, is left untouched —
// NetworkAllowed() checks it first and it always wins, by design (see that
// file's doc comment on the override precedence).
func applyNetworkPolicy(cmd *cobra.Command) {
	allow, _ := cmd.Flags().GetBool("network")
	if allow {
		_ = os.Setenv("DSD_ALLOW_NETWORK", "1")
	}
}

// networkFlagExempt lists commands whose network calls target operator-named
// hosts at invocation time (fleet: SSH/SCP args; tls: --endpoint(s); update:
// the GitHub release download) rather than the ambient, on-your-behalf calls
// --network/DSD_ALLOW_NETWORK gates. Their --help should not advertise a flag
// that has no effect on them — see each command's Long text for the full
// explanation shown alongside the flag's removal here.
var networkFlagExempt = map[string]bool{
	"fleet":  true,
	"tls":    true,
	"update": true,
}

func init() {
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
	// Help = the command's description (Long, else Short) followed by usage.
	// The previous func called Usage() only, which silently dropped every
	// command's description — so `dsd --help` showed 35 commands with no tagline
	// or "start here" guidance for a first-time user.
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		desc := cmd.Long
		if desc == "" {
			desc = cmd.Short
		}
		if desc != "" {
			fmt.Fprintln(cmd.OutOrStderr(), desc)
			fmt.Fprintln(cmd.OutOrStderr())
		}
		if networkFlagExempt[cmd.Name()] {
			printUsageWithoutNetworkFlag(cmd)
			return
		}
		cmd.Usage() //nolint:errcheck
	})

	f := rootCmd.PersistentFlags()
	f.Bool("plain", false, "plain text output (no colour, machine-friendly)")
	f.Bool("json", false, "JSON output (machine-readable)")
	f.String("out", "", "write output to file")
	// White-label the HTML reports (--report-html) with a company name + logo, so an
	// MSP/consultancy can hand a client a report under its own brand. Also settable via
	// DSD_BRAND_COMPANY / DSD_BRAND_LOGO env vars.
	f.String("brand", "", "company name to white-label HTML reports with (or set DSD_BRAND_COMPANY)")
	f.String("logo", "", "path to a logo image embedded in HTML reports (or set DSD_BRAND_LOGO)")
	// Network calls are off by default (PRIVACY.md's "no network calls, ever"
	// promise) — opt in per-run with --network, or persistently with
	// DSD_ALLOW_NETWORK=1 for scripted/CI use. DSD_OFFLINE=1 always forces
	// offline and overrides both, even together — see
	// internal/platform/network_policy.go.
	f.Bool("network", false, "allow outbound network calls (also: DSD_ALLOW_NETWORK=1). DSD_OFFLINE=1 always overrides both and forces offline")
	f.Bool("watch", false, "watch mode — refresh periodically")
	f.Bool("share", false, "share report via URL")
	f.Bool("qr", false, "display share URL as QR code")

	// Hide --share and --qr from --help until the share backend ships.
	// Flags remain valid (no breaking change) but don't appear in help text
	// so users don't see features that don't work yet.
	_ = f.MarkHidden("share")
	_ = f.MarkHidden("qr")
}

// printUsageWithoutNetworkFlag renders cmd's usage exactly like cmd.Usage(),
// minus the --network line. MarkHidden can't scope this to one command:
// --network lives on rootCmd.PersistentFlags(), and every command that
// inherits it shares the same underlying *pflag.Flag pointer, so
// pflag.Flag.Hidden is one field on one shared object — marking it hidden via
// any single command's FlagSet hides it from every command's --help, not
// just this one (verified empirically: doing so via fleet's FlagSet also
// hid --network from `dsd health --help`). Filtering the rendered text is
// the only way to scope the omission to networkFlagExempt commands without
// mutating that shared state.
func printUsageWithoutNetworkFlag(cmd *cobra.Command) {
	var buf bytes.Buffer
	out := cmd.OutOrStderr()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	_ = cmd.Usage()

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, "--network ") {
			continue
		}
		kept = append(kept, line)
	}
	fmt.Fprintln(out, strings.Join(kept, "\n"))
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(exitCodeForExecuteError(err))
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
