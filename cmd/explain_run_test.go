package cmd

// explain_run_test.go covers runExplain's flag-dispatch branches (markdown,
// --all, --search, no-args list, found/ambiguous/not-found topic lookup, and
// the JSON-mode single-topic path) plus explainCmd's ValidArgsFunction
// completion closure (registered in explain.go's init()). explain.Topics()/
// Lookup()/Search()/Markdown() are static, in-memory, no-I/O — safe to call
// directly, same rationale as explain_report_test.go.

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/explain"
)

// newBareExplainCmd builds a bare cobra.Command with the flags runExplain reads.
func newBareExplainCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("plain", false, "")
	f.Bool("json", false, "")
	f.Bool("all", false, "")
	f.String("search", "", "")
	f.Bool("markdown", false, "")
	return c
}

func TestRunExplainMarkdown(t *testing.T) {
	c := newBareExplainCmd()
	_ = c.Flags().Set("markdown", "true")
	out := captureStdout(t, func() {
		if err := runExplain(c, nil); err != nil {
			t.Fatalf("runExplain --markdown: %v", err)
		}
	})
	if out != explain.Markdown() {
		t.Errorf("--markdown should print explain.Markdown() verbatim")
	}
}

func TestRunExplainAll(t *testing.T) {
	c := newBareExplainCmd()
	_ = c.Flags().Set("all", "true")
	_ = c.Flags().Set("plain", "true")
	out := captureStdout(t, func() {
		if err := runExplain(c, nil); err != nil {
			t.Fatalf("runExplain --all: %v", err)
		}
	})
	topics := explain.Topics()
	if len(topics) == 0 {
		t.Skip("no topics available")
	}
	if !strings.Contains(out, topics[0].Title) {
		t.Errorf("--all should render every topic, missing %q in:\n%s", topics[0].Title, out)
	}
}

func TestRunExplainSearch(t *testing.T) {
	c := newBareExplainCmd()
	_ = c.Flags().Set("search", "disk")
	_ = c.Flags().Set("plain", "true")
	out := captureStdout(t, func() {
		if err := runExplain(c, nil); err != nil {
			t.Fatalf("runExplain --search disk: %v", err)
		}
	})
	if !strings.Contains(out, "disk") {
		t.Errorf("--search disk should surface the disk topic, got:\n%s", out)
	}
}

func TestRunExplainNoArgsListsTopics(t *testing.T) {
	c := newBareExplainCmd()
	_ = c.Flags().Set("plain", "true")
	out := captureStdout(t, func() {
		if err := runExplain(c, nil); err != nil {
			t.Fatalf("runExplain (no args): %v", err)
		}
	})
	if !strings.Contains(out, "dsd explain <topic>") {
		t.Errorf("no-args should list topics, got:\n%s", out)
	}
}

func TestRunExplainFoundTopicPlain(t *testing.T) {
	c := newBareExplainCmd()
	_ = c.Flags().Set("plain", "true")
	out := captureStdout(t, func() {
		if err := runExplain(c, []string{"disk"}); err != nil {
			t.Fatalf("runExplain disk: %v", err)
		}
	})
	if !strings.Contains(out, "Filesystem capacity") {
		t.Errorf("a found topic should render its detail, got:\n%s", out)
	}
}

func TestRunExplainFoundTopicJSON(t *testing.T) {
	c := newBareExplainCmd()
	_ = c.Flags().Set("json", "true")
	out := captureStdout(t, func() {
		if err := runExplain(c, []string{"disk"}); err != nil {
			t.Fatalf("runExplain --json disk: %v", err)
		}
	})
	if !strings.Contains(out, `"key"`) {
		t.Errorf("--json with a topic arg should emit the topic as JSON, got:\n%s", out)
	}
}

func TestRunExplainNotFoundTopic(t *testing.T) {
	c := newBareExplainCmd()
	err := runExplain(c, []string{"zzz-nonexistent-zzz"})
	if err == nil {
		t.Fatal("an unknown topic should return an error")
	}
	if !strings.Contains(err.Error(), "no topic") {
		t.Errorf("unexpected error for an unknown topic: %v", err)
	}
}

func TestRunExplainAmbiguousTopic(t *testing.T) {
	// "nd" is a substring of both the "bind" and "bonding" keys, with no
	// exact key/alias match of its own — an ambiguous fuzzy match.
	c := newBareExplainCmd()
	err := runExplain(c, []string{"nd"})
	if err == nil {
		t.Fatal("an ambiguous topic query should return an error")
	}
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("expected an 'ambiguous' error, got: %v", err)
	}
}

// TestExplainValidArgsFunction covers the tab-completion closure registered
// in explain.go's init(). With no args it lists every topic key; with an arg
// already present it returns no further completions.
func TestExplainValidArgsFunction(t *testing.T) {
	fn := explainCmd.ValidArgsFunction
	if fn == nil {
		t.Fatal("explainCmd.ValidArgsFunction should be registered")
	}
	keys, directive := fn(explainCmd, nil, "")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("directive = %v, want ShellCompDirectiveNoFileComp", directive)
	}
	if len(keys) == 0 {
		t.Error("with no args, ValidArgsFunction should list topic keys")
	}

	keys2, directive2 := fn(explainCmd, []string{"disk"}, "")
	if directive2 != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("directive = %v, want ShellCompDirectiveNoFileComp", directive2)
	}
	if keys2 != nil {
		t.Errorf("with an arg already given, ValidArgsFunction should return no keys, got %v", keys2)
	}
}
