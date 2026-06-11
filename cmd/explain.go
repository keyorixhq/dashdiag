package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/explain"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
)

func init() {
	rootCmd.AddCommand(explainCmd)
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
  dsd explain zfs --json machine-readable`,
	Args: cobra.MaximumNArgs(1),
	RunE: runExplain,
}

func runExplain(cmd *cobra.Command, args []string) error {
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	mode := output.DetectMode(plain, false, jsonModeStr(jsonOut))

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
