package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/explain"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
)

// printHealthExplanations is the `dsd health --explain` tail: after the verdict,
// it appends a compact explanation for each subsystem that produced a WARN/CRIT,
// deduped by topic and shown in the order the insights appear. Human/plain only;
// structured output already carries the insight data.
func printHealthExplanations(insights []models.Insight, mode output.OutputMode) {
	if mode != output.ModeHuman && mode != output.ModePlain {
		return
	}
	seen := map[string]bool{}
	var matched []explain.Topic
	for _, ins := range insights {
		if ins.Level != "WARN" && ins.Level != "CRIT" {
			continue
		}
		t := explain.ForCheck(ins.Check)
		if t == nil || seen[t.Key] {
			continue
		}
		seen[t.Key] = true
		matched = append(matched, *t)
	}
	if len(matched) == 0 {
		return
	}
	human := mode == output.ModeHuman
	bold := func(s string) string {
		if human {
			return render.StyleBold.Render(s)
		}
		return s
	}
	dim := func(s string) string {
		if human {
			return render.StyleDim.Render(s)
		}
		return s
	}
	fmt.Println()
	fmt.Println(bold("Why these matter") + dim("  ·  dsd explain <topic> for full detail"))
	for _, t := range matched {
		fmt.Printf("\n  %s — %s\n    %s\n", bold(t.Title), dim(t.Summary), t.Matters)
		if len(t.Fix) > 0 {
			fmt.Printf("    %s %s\n", dim("fix:"), strings.Join(t.Fix, "; "))
		}
	}
}

// printHealthFixes is the `dsd health --fix` tail: after the verdict, it
// consolidates the "to fix:" remediation commands from every WARN/CRIT insight
// into one copy-pasteable block, grouped by subsystem and deduped. Pure
// aggregation of hints the verdict already produced. Human/plain only.
// healthFixGroup is the remediation commands for one subsystem.
type healthFixGroup struct {
	check string
	cmds  []string
}

// healthFixGroups extracts the "to fix:" commands from WARN/CRIT insights, grouped
// by subsystem in first-seen order and deduped by (check, command). Pure — no I/O.
func healthFixGroups(insights []models.Insight) []healthFixGroup {
	var groups []healthFixGroup
	idx := map[string]int{}
	seen := map[string]bool{}
	for _, ins := range insights {
		if ins.Level != "WARN" && ins.Level != "CRIT" {
			continue
		}
		for _, h := range ins.Hints {
			rest, ok := strings.CutPrefix(h, "to fix:")
			if !ok {
				continue
			}
			cmd := strings.TrimSpace(rest)
			if cmd == "" {
				continue
			}
			key := ins.Check + "|" + cmd
			if seen[key] {
				continue
			}
			seen[key] = true
			gi, ok := idx[ins.Check]
			if !ok {
				gi = len(groups)
				groups = append(groups, healthFixGroup{check: ins.Check})
				idx[ins.Check] = gi
			}
			groups[gi].cmds = append(groups[gi].cmds, cmd)
		}
	}
	return groups
}

func printHealthFixes(insights []models.Insight, mode output.OutputMode) {
	if mode != output.ModeHuman && mode != output.ModePlain {
		return
	}
	groups := healthFixGroups(insights)
	if len(groups) == 0 {
		return
	}
	human := mode == output.ModeHuman
	bold := func(s string) string {
		if human {
			return render.StyleBold.Render(s)
		}
		return s
	}
	dim := func(s string) string {
		if human {
			return render.StyleDim.Render(s)
		}
		return s
	}
	fmt.Println()
	fmt.Println(bold("Suggested fixes") + dim("  ·  review before running; some need sudo"))
	for _, g := range groups {
		fmt.Printf("\n  %s\n", bold(g.check))
		for _, c := range g.cmds {
			fmt.Printf("    %s %s\n", dim("$"), c)
		}
	}
}

func init() {
	rootCmd.AddCommand(explainCmd)
	explainCmd.Flags().Bool("all", false, "print full detail for every topic (e.g. dsd explain --all > checks.md)")
	// Tab-complete topic names: `dsd explain <TAB>`.
	explainCmd.ValidArgsFunction = func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		var keys []string
		for _, t := range explain.Topics() {
			keys = append(keys, t.Key)
		}
		return keys, cobra.ShellCompDirectiveNoFileComp
	}
}

var explainCmd = &cobra.Command{
	Use:   "explain [topic]",
	Short: "Explain what a health check diagnoses, why it matters, and how to fix it",
	Long: `Plain-language reference for dsd's health checks. With no argument it lists the
available topics; with a topic it prints what the check looks at, why it matters,
how dsd decides severity, and the commands to investigate and fix it.

This is static documentation — it never touches the host, so it can't be wrong
about your system. Pair it with a finding: when dsd health flags Swap, run
` + "`dsd explain swap`" + `.

Examples:
  dsd explain            list all topics
  dsd explain swap       explain the swap check
  dsd explain ram        aliases resolve (→ memory)
  dsd explain zfs --json machine-readable
  dsd explain --all      full detail for every topic (pipe to a reference file)`,
	Args: cobra.MaximumNArgs(1),
	RunE: runExplain,
}

func runExplain(cmd *cobra.Command, args []string) error {
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	mode := output.DetectMode(plain, false, jsonModeStr(jsonOut))

	if allFlag, _ := cmd.Flags().GetBool("all"); allFlag {
		return explainAll(mode)
	}
	if len(args) == 0 {
		return explainList(mode)
	}

	topic, candidates := explain.Lookup(args[0])
	if topic == nil {
		if len(candidates) > 0 {
			return fmt.Errorf("%q is ambiguous — did you mean: %s", args[0], strings.Join(candidates, ", "))
		}
		return fmt.Errorf("no topic %q. Run `dsd explain` to list topics", args[0])
	}

	if mode == output.ModeJSON || mode == output.ModeYAML {
		b, err := json.MarshalIndent(topic, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	printTopic(*topic, mode)
	return nil
}

func jsonModeStr(jsonOut bool) string {
	if jsonOut {
		return "json"
	}
	return ""
}

func explainList(mode output.OutputMode) error {
	all := explain.Topics()
	if mode == output.ModeJSON || mode == output.ModeYAML {
		b, err := json.MarshalIndent(all, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	human := mode == output.ModeHuman
	heading := "Topics — run `dsd explain <topic>` for detail:"
	if human {
		heading = render.StyleBold.Render(heading)
	}
	fmt.Println(heading)
	fmt.Println()
	for _, t := range all {
		key := fmt.Sprintf("  %-12s", t.Key)
		if human {
			key = "  " + render.StyleBold.Render(fmt.Sprintf("%-10s", t.Key))
		}
		fmt.Printf("%s %s\n", key, t.Summary)
	}
	return nil
}

// explainAll prints full detail for every topic — a complete checks reference.
// In structured modes it emits the same JSON array as the topic list.
func explainAll(mode output.OutputMode) error {
	all := explain.Topics()
	if mode == output.ModeJSON || mode == output.ModeYAML {
		b, err := json.MarshalIndent(all, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	for i, t := range all {
		if i > 0 {
			sep := "────────────────────────────────────────────────────────"
			if mode == output.ModeHuman {
				sep = render.StyleDim.Render(sep)
			}
			fmt.Println("\n" + sep)
		}
		printTopic(t, mode)
	}
	return nil
}

func printTopic(t explain.Topic, mode output.OutputMode) {
	human := mode == output.ModeHuman
	bold := func(s string) string {
		if human {
			return render.StyleBold.Render(s)
		}
		return s
	}
	dim := func(s string) string {
		if human {
			return render.StyleDim.Render(s)
		}
		return s
	}

	fmt.Printf("\n%s — %s\n\n", bold(t.Title), t.Summary)
	section := func(label, body string) {
		fmt.Printf("%s\n  %s\n\n", bold(label), body)
	}
	section("What it checks", t.Checks)
	section("Why it matters", t.Matters)
	section("How dsd decides", t.Verdict)

	if len(t.Look) > 0 {
		fmt.Println(bold("Investigate"))
		for _, c := range t.Look {
			fmt.Printf("  %s %s\n", dim("$"), c)
		}
		fmt.Println()
	}
	if len(t.Fix) > 0 {
		fmt.Println(bold("Fix"))
		for _, c := range t.Fix {
			fmt.Printf("  %s %s\n", dim("→"), c)
		}
		fmt.Println()
	}
	if len(t.Aliases) > 0 {
		sorted := append([]string(nil), t.Aliases...)
		sort.Strings(sorted)
		fmt.Println(dim("aliases: " + strings.Join(sorted, ", ")))
	}
}
