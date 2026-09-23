package cmd

// demo.go — `dsd demo [scenario]`
//
// The zero-friction "wow" command for a person who just installed dsd on a
// clean laptop: no arguments, no files, no network, under 10 seconds, and it
// shows the causal-chain diagnosis a healthy box can never demonstrate. Renders
// through the EXACT same pipeline `dsd mock` uses (PrintAllMock/PrintSummary) —
// no new inference or renderer code — against a curated, embedded scenario
// instead of a user-supplied fixture file. See internal/demo for the embedded
// scenario set and docs/DEMO_FIXTURES.md for the distinction from `dsd mock`.
//
// Always exits 0, regardless of the simulated verdict: this is a marketing/
// distribution feature showing simulated data, never a live host gate a script
// could mistake for a real result (see contract_test.go's exitCodeContract).

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/dashdiag/internal/demo"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/version"
)

var demoCmd = &cobra.Command{
	Use:   "demo [scenario]",
	Short: "See a real diagnosis in 10 seconds — no hardware, no files, no network",
	Long: `Renders a simulated-but-realistic dsd health output for a broken host, using
the exact same render pipeline as a live run — so you can see what dsd catches
before pointing it at a real machine.

  dsd demo               the flagship scenario (a failing drive)
  dsd demo --list        list every available scenario
  dsd demo <name>        render a specific scenario

Always exits 0 — this is simulated data, not a live host result. Scripts must
never branch on dsd demo's exit code the way they might dsd health's.`,
	Args: cobra.MaximumNArgs(1),
	// Suppress the root brand header (which would print this machine's real
	// hostname/OS) — demo prints its own "simulated host" banner instead, same
	// pattern as `dsd mock`.
	PersistentPreRun: func(cmd *cobra.Command, _ []string) { applyNetworkPolicy(cmd) },
	RunE:             runDemo,
}

func init() {
	rootCmd.AddCommand(demoCmd)
	demoCmd.Flags().Bool("list", false, "list available demo scenarios")
}

func runDemo(cmd *cobra.Command, args []string) error {
	if listOnly, _ := cmd.Flags().GetBool("list"); listOnly {
		printDemoList()
		return nil
	}

	name := demo.Default()
	if len(args) == 1 {
		name = args[0]
	}

	raw, err := demo.Load(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsd: demo: unknown scenario %q\n\n", name)
		printDemoList()
		return fmt.Errorf("unknown demo scenario %q", name)
	}

	var fix MockFixture
	if uerr := yaml.Unmarshal(raw, &fix); uerr != nil {
		return fmt.Errorf("invalid embedded demo scenario %q: %w", name, uerr)
	}

	results, insights := mockFixtureResults(fix)

	// Carry the scenario's simulated identity into the render/JSON output
	// instead of this machine's real hostname/OS — the same mechanism `dsd
	// replay` uses to carry a captured host's identity (platform.SetIdentity).
	restore := platform.SetIdentity(fix.Host, fix.OS)
	defer restore()

	if jsonOut, _ := cmd.Flags().GetBool("json"); jsonOut {
		return printDemoJSON(results, insights)
	}

	printDemoBanner(fix)

	plain, _ := cmd.Flags().GetBool("plain")
	r := render.NewRenderer(output.DetectMode(plain, false, ""))
	r.PrintAllMock(results, insights, mockInlineFunc(fix.Rows))

	start := time.Now().Add(-3 * time.Second) // simulate a ~3s run, like dsd mock
	r.PrintSummary(insights, time.Since(start))

	printDemoNarrative(fix.Narrative)

	return nil
}

// printDemoBanner prints the "this is not your machine" disclaimer dsd demo's
// spec requires, then the same host/OS/rule-line dsd mock prints — sanitized,
// since host/os come from the fixture (untrusted by the same standard as any
// fixture — see mock.go's identical sanitization of these two fields).
func printDemoBanner(fix MockFixture) {
	v := fix.Version
	if v == "" {
		v = version.Version
	}
	host := fix.Host
	if host == "" {
		host = "demo-host"
	}
	osName := fix.OS
	if osName == "" {
		osName = "Linux"
	}
	fmt.Fprintf(os.Stderr, "⚡ DashDiag (dsd) %s — DEMO: simulated host, not this machine. Run `sudo dsd health` for yours.\n", v)
	fmt.Fprintf(os.Stderr, "%s · %s\n", output.SanitizeControl(host), output.SanitizeControl(osName))
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("─", 56))
}

// printDemoNarrative prints the fixture's 3-5 line "what happened, why, what
// to do" story after the summary. Narrative text is authored fixture content
// (not collector output), but sanitized anyway at this single print site for
// the same reason every other rendered fixture field is (mock.go, health.go).
func printDemoNarrative(lines []string) {
	if len(lines) == 0 {
		return
	}
	fmt.Println()
	for _, line := range lines {
		fmt.Println(output.SanitizeControl(line))
	}
}

// printDemoList prints every embedded scenario with its one-line description,
// marking the default.
func printDemoList() {
	fmt.Fprintln(os.Stdout, "Available dsd demo scenarios:")
	fmt.Fprintln(os.Stdout)
	for _, s := range demo.List() {
		marker := "  "
		if s.Name == demo.Default() {
			marker = "* "
		}
		fmt.Fprintf(os.Stdout, "%s%-28s %s\n", marker, s.Name, s.Description)
	}
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "* = default (dsd demo with no arguments)")
	fmt.Fprintln(os.Stdout, "Run one: dsd demo <name>")
}

// demoJSONOutput extends the standard dsd health --json contract with a single
// additive top-level field. Embedding render.JSONOutput (rather than building a
// map) preserves its field order and keeps this the same schema plus one field,
// per the additive-only JSON contract rule (docs/ARCHITECTURE.md).
type demoJSONOutput struct {
	render.JSONOutput
	Demo bool `json:"demo"`
}

func printDemoJSON(results []runner.Result, insights []models.Insight) error {
	out := demoJSONOutput{JSONOutput: render.BuildJSONOutput(results, insights), Demo: true}
	return outputJSON(os.Stdout, out)
}
