package cmd

// migrate.go — `dsd migrate baseline` + `dsd migrate certify`
//
// Landing-zone certification for a hypervisor/cloud migration. Capture a baseline on
// the SOURCE guest before the move, certify on the DESTINATION guest after it, and get
// a PASS / PASS-WITH-WARNINGS / FAIL verdict plus exactly what regressed. Read-only on
// both sides — dsd never moves data; the mover does that (ADR-0006). This is packaging
// over shipped machinery: capture/replay (ADR-0003), baseline.ComputeDiff, the health
// collectors (VMware/driver/cloud-init/disk-grown), and the standard diff renderer.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/source"
	"github.com/spf13/cobra"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Certify a Linux guest came across a hypervisor/cloud migration clean",
	Long: `Landing-zone certification for a VM/guest migration (VMware->Proxmox, on-prem->cloud,
cloud repatriation, ...). Read-only on both sides — dsd diagnoses, it never moves data.

  dsd migrate baseline                       # on the SOURCE guest, before the move
  dsd migrate certify src.tar.gz dst.tar.gz  # compare source baseline vs landed guest

The workflow: capture a baseline on the source, migrate with whatever mover you like,
capture the destination, then certify. certify replays both captures through the same
health pipeline and reports what changed — drivers that fell back to emulated, guest
tools now stale, cloud-init that did not run, an unresized disk, security posture that
drifted — with a PASS / PASS-WITH-WARNINGS / FAIL verdict.`,
}

var migrateBaselineCmd = &cobra.Command{
	Use:              "baseline",
	Short:            "Capture a pre-migration baseline on the SOURCE guest",
	Long:             `Capture a portable baseline bundle on the source guest before migrating, and print a readiness summary (pre-existing issues you should resolve before the move). The bundle is a dsd capture --raw bundle; carry it to the destination for 'dsd migrate certify'.`,
	Args:             cobra.NoArgs,
	PersistentPreRun: func(_ *cobra.Command, _ []string) { /* suppress brand header */ },
	RunE:             runMigrateBaseline,
}

var migrateCertifyCmd = &cobra.Command{
	Use:              "certify <source-baseline.tar.gz> <destination.tar.gz>",
	Short:            "Certify the destination guest against the source baseline",
	Long:             `Replay the source baseline and the destination capture through the identical health pipeline and certify the migration: PASS / PASS-WITH-WARNINGS / FAIL, with every check that regressed. A source-only check that gates off after the move (e.g. VMware guest tools) is EXPECTED and not counted against the verdict; only a check that got worse on the destination is a regression.`,
	Args:             cobra.ExactArgs(2),
	PersistentPreRun: func(_ *cobra.Command, _ []string) { /* suppress brand header */ },
	RunE:             runMigrateCertify,
}

func init() {
	rootCmd.AddCommand(migrateCmd)
	migrateCmd.AddCommand(migrateBaselineCmd)
	migrateCmd.AddCommand(migrateCertifyCmd)

	// baseline mirrors the capture --raw flags that runCaptureRaw reads.
	migrateBaselineCmd.Flags().StringP("out", "o", "", "output path for the baseline bundle")
	migrateBaselineCmd.Flags().Bool("deep", false, "include deep collectors in the baseline")
	migrateBaselineCmd.Flags().Bool("pkg", false, "include the package collector")
	migrateBaselineCmd.Flags().Bool("cve-scan", false, "record a CVE scan into the baseline")
	migrateBaselineCmd.Flags().Bool("sanitize", false, "redact secrets before writing the baseline")
	migrateBaselineCmd.Flags().Bool("identifiers", false, "also redact IPs/MACs/hostnames (implies --sanitize)")

	migrateCertifyCmd.Flags().Bool("json", false, "machine-readable certification report")
	migrateCertifyCmd.Flags().Bool("deep", false, "replay deep collectors")
	migrateCertifyCmd.Flags().Bool("pkg", false, "replay the package collector")
	migrateCertifyCmd.Flags().Bool("force", false, "certify even if a bundle's OS differs from this binary (output not faithful)")
}

func runMigrateBaseline(cmd *cobra.Command, _ []string) error {
	out, _ := cmd.Flags().GetString("out")
	if out == "" {
		out = fmt.Sprintf("dsd-migrate-baseline-%s-%s.tar.gz", hostnameOr("host"), time.Now().Format("20060102-150405"))
		_ = cmd.Flags().Set("out", out)
	}
	fmt.Fprintln(os.Stderr, "Capturing pre-migration baseline (source guest)…")
	if err := runCaptureRaw(cmd); err != nil {
		return err
	}
	// Readiness summary — replay the baseline we just wrote and flag pre-existing
	// problems. Resolving these BEFORE the move avoids blaming the migration for a
	// fault that was already there (and dirtying the certification diff).
	b, err := loadBundle(out)
	if err != nil {
		return fmt.Errorf("reading baseline for readiness summary: %w", err)
	}
	_, insights, _ := replayBundle(b, false, false, false, false)
	printMigrationReadiness(out, insights)
	return nil
}

func printMigrationReadiness(path string, insights []models.Insight) {
	var crit, warn int
	for _, in := range insights {
		switch statusSeverity(in.Level) {
		case sevCrit:
			crit++
		case sevWarn:
			warn++
		}
	}
	fmt.Println()
	fmt.Printf("Migration baseline written: %s\n", path)
	fmt.Println("Carry this bundle to the destination and run: dsd migrate certify <this> <destination>")
	fmt.Println()
	switch {
	case crit > 0:
		fmt.Printf("Pre-flight readiness: %d critical, %d warning issue(s) on the SOURCE.\n", crit, warn)
		fmt.Println("  → Resolve the critical issues BEFORE migrating — they are not the migration's fault,")
		fmt.Println("    and leaving them makes the post-move certification harder to read.")
	case warn > 0:
		fmt.Printf("Pre-flight readiness: %d warning(s) on the SOURCE, no critical issues — OK to migrate.\n", warn)
	default:
		fmt.Println("Pre-flight readiness: clean source, no pre-existing issues — good to migrate.")
	}
}

func runMigrateCertify(cmd *cobra.Command, args []string) error {
	force, _ := cmd.Flags().GetBool("force")
	deep, _ := cmd.Flags().GetBool("deep")
	pkg, _ := cmd.Flags().GetBool("pkg")
	jsonOut, _ := cmd.Flags().GetBool("json")

	src, err := loadBundle(args[0])
	if err != nil {
		return fmt.Errorf("loading source baseline bundle: %w", err)
	}
	dst, err := loadBundle(args[1])
	if err != nil {
		return fmt.Errorf("loading destination bundle: %w", err)
	}
	if err := replayPlatformGuard(src, force); err != nil {
		return err
	}
	if err := replayPlatformGuard(dst, force); err != nil {
		return err
	}

	_, _, srcSnap := replayBundle(src, deep, pkg, false, false)
	_, _, dstSnap := replayBundle(dst, deep, pkg, false, false)

	diff := baseline.ComputeDiff(srcSnap, dstSnap)
	verdict, regressions := certifyVerdict(diff)

	if jsonOut {
		return emitCertifyJSON(src, dst, verdict, regressions)
	}
	printCertifyReport(src, dst, verdict, regressions, srcSnap, dstSnap)
	switch verdict {
	case certFail:
		recordExitCode(2)
	case certWarn:
		recordExitCode(1)
	}
	return nil
}

const (
	certPass = "PASS"
	certWarn = "PASS-WITH-WARNINGS"
	certFail = "FAIL"
)

// status severity ranks, tolerant of the health status vocabulary.
const (
	sevOK      = 0
	sevUnknown = 1
	sevWarn    = 2
	sevCrit    = 3
)

// statusSeverity maps a status/level token to a rank. Used by both the
// pre-flight readiness tally (printMigrationReadiness) and certifyVerdict's
// regression detection below — the latter re-derives severity from the
// Before/After strings rather than trusting DiffEntry.Improved directly,
// since certify compares two DIFFERENT hosts (source vs. destination) and
// needs its own PASS/WARN/FAIL tiering (sevWarn vs sevCrit), not just a
// boolean. INFO — a collector that couldn't measure something, dsd's "not
// verified" vocabulary — ranks as unknown, not OK: it must never be conflated
// with a confirmed-healthy reading. (baseline.DiffEntry.Unverified now marks
// this same state structurally for same-host diffing — see ComputeDiff.)
func statusSeverity(s string) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRIT", "CRITICAL", "FAIL":
		return sevCrit
	case "WARN", "WARNING":
		return sevWarn
	case "UNKNOWN", "INFO":
		return sevUnknown
	default:
		return sevOK
	}
}

// firstToken returns the leading status word of a DiffEntry Before/After string, which
// ComputeDiff formats as "STATUS value" (or "absent").
func firstToken(s string) string {
	s = strings.TrimSpace(s)
	if before, _, ok := strings.Cut(s, " "); ok {
		return before
	}
	return s
}

// certifyVerdict derives the certification from the diff. A REGRESSION is a check
// whose status got strictly worse on the destination (OK->WARN, WARN->CRIT, new
// WARN/CRIT) — OR a confirmed problem (WARN/CRIT on the source) that became
// unverifiable (INFO — a collector that couldn't measure it) on the destination.
// The plain severity ordering alone doesn't catch that second case: INFO ranks
// below WARN/CRIT (it means "unknown," not "healthy"), so a naive comparison reads
// CRIT->INFO as an improvement, when really certify just couldn't confirm the
// problem is gone. That must downgrade the verdict, never silently PASS.
//
// A whole check that VANISHES (After == "absent") is treated differently: certify
// compares two different platforms (source vs. destination), where a check's whole
// subsystem legitimately not applying anymore (e.g. VMware guest tools on a
// non-VMware landing zone) is expected, not a regression — unlike `dsd diff`'s
// same-host-over-time comparison, where a vanished check is always suspicious and
// ComputeDiff's own bucketing (which this function otherwise leaves alone) treats
// it as degraded for that reason.
func certifyVerdict(diff []baseline.DiffEntry) (string, []baseline.DiffEntry) {
	verdict := certPass
	var regressions []baseline.DiffEntry
	for _, e := range diff {
		afterToken := firstToken(e.After)
		if strings.EqualFold(afterToken, "absent") {
			continue
		}
		before := statusSeverity(firstToken(e.Before))
		after := statusSeverity(afterToken)
		regression := after > before || (before >= sevWarn && after == sevUnknown)
		if !regression {
			continue
		}
		regressions = append(regressions, e)
		switch {
		case after >= sevCrit:
			verdict = certFail
		case verdict != certFail:
			verdict = certWarn
		}
	}
	return verdict, regressions
}

func printCertifyReport(src, dst *source.Bundle, verdict string, regressions []baseline.DiffEntry, srcSnap, dstSnap *baseline.Snapshot) {
	mark := map[string]string{certPass: "✅", certWarn: "⚠️", certFail: "❌"}[verdict]
	fmt.Printf("%s  MIGRATION CERTIFICATION: %s\n", mark, verdict)
	fmt.Println(strings.Repeat("─", 60))
	// Manifest.Host/OS are trivially forgeable bundle content (a source or
	// destination bundle handed to an engineer for a migration issue) —
	// sanitize before the human-readable report reaches the terminal. The
	// --json path (emitCertifyJSON) is unaffected: encoding/json already
	// \u-escapes control bytes below 0x20.
	fmt.Printf("source:      %s (%s)\n", output.SanitizeControl(manifestHost(src)), output.SanitizeControl(manifestOS(src)))
	fmt.Printf("destination: %s (%s)\n", output.SanitizeControl(manifestHost(dst)), output.SanitizeControl(manifestOS(dst)))
	fmt.Println()

	switch {
	case len(regressions) == 0:
		fmt.Println("No regressions: every check on the destination is as healthy as (or")
		fmt.Println("healthier than) the source baseline. The guest came across clean.")
	default:
		fmt.Printf("%d regression(s) — checks that got WORSE after the move:\n", len(regressions))
		for _, r := range regressions {
			fmt.Printf("  • %-22s %s → %s\n", r.Name, firstToken(r.Before), firstToken(r.After))
		}
	}
	fmt.Println()
	fmt.Println("Note: source-only checks that gate off after the move (e.g. VMware guest")
	fmt.Println("tools no longer relevant on the destination) are EXPECTED, not regressions.")
	fmt.Println()
	fmt.Println("Full before/after detail:")
	fmt.Println(strings.Repeat("─", 60))
	_ = render.PrintDiff(os.Stdout, srcSnap, dstSnap, output.ModeHuman)
}

type certifyJSON struct {
	Verdict     string              `json:"verdict"`
	Source      certifyEndpoint     `json:"source"`
	Destination certifyEndpoint     `json:"destination"`
	Regressions []certifyRegression `json:"regressions"`
}

type certifyEndpoint struct {
	Host    string `json:"host"`
	OS      string `json:"os"`
	Created string `json:"created"`
}

type certifyRegression struct {
	Name   string `json:"name"`
	Before string `json:"before"`
	After  string `json:"after"`
}

func emitCertifyJSON(src, dst *source.Bundle, verdict string, regressions []baseline.DiffEntry) error {
	out := certifyJSON{
		Verdict:     verdict,
		Source:      certifyEndpoint{Host: manifestHost(src), OS: manifestOS(src), Created: src.Manifest.Created},
		Destination: certifyEndpoint{Host: manifestHost(dst), OS: manifestOS(dst), Created: dst.Manifest.Created},
	}
	for _, r := range regressions {
		out.Regressions = append(out.Regressions, certifyRegression{Name: r.Name, Before: firstToken(r.Before), After: firstToken(r.After)})
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	switch verdict {
	case certFail:
		recordExitCode(2)
	case certWarn:
		recordExitCode(1)
	}
	return nil
}

func manifestHost(b *source.Bundle) string {
	if b == nil {
		return "?"
	}
	if b.Manifest.Host != "" {
		return b.Manifest.Host
	}
	return "unknown"
}

func manifestOS(b *source.Bundle) string {
	if b == nil {
		return "?"
	}
	if b.Manifest.OS != "" {
		return b.Manifest.OS
	}
	return b.Manifest.GOOS
}
