package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/explain"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for explain.go's renderers. explain.Topics()/Search()
// return a static in-memory list (no I/O) — safe to call directly. No
// t.Parallel() (corrupts captureStdout's shared os.Stdout swap).

func TestExplainList(t *testing.T) {
	out := captureStdout(t, func() { _ = explainList(output.ModePlain) })
	if !strings.Contains(out, "dsd explain <topic>") {
		t.Errorf("the topic list should point to the detail command, got:\n%s", out)
	}
	// The real topic set is non-empty and static; spot-check a well-known key
	// exists so this test fails loudly if the topic list is ever emptied.
	if len(explain.Topics()) == 0 {
		t.Fatal("explain.Topics() returned no topics — the static topic list may have regressed")
	}
}

func TestExplainSearchNoHits(t *testing.T) {
	out := captureStdout(t, func() { _ = explainSearch("zzz-nonexistent-keyword-zzz", output.ModePlain) })
	if !strings.Contains(out, "No topics mention") {
		t.Errorf("a keyword with no hits should say so, got:\n%s", out)
	}
}

func TestExplainSearchWithHits(t *testing.T) {
	// Search on a topic's own key guarantees at least one hit without
	// depending on any specific topic's prose content.
	topics := explain.Topics()
	if len(topics) == 0 {
		t.Skip("no topics available")
	}
	out := captureStdout(t, func() { _ = explainSearch(topics[0].Key, output.ModePlain) })
	if !strings.Contains(out, topics[0].Key) {
		t.Errorf("searching a topic's own key should surface it, got:\n%s", out)
	}
}

func TestPrintTopic(t *testing.T) {
	topic := explain.Topic{
		Key: "disk", Title: "Disk Health", Summary: "SMART + filesystem usage",
		Checks: "SMART status, usage %%", Matters: "silent data loss", Verdict: "WARN at 80%%, CRIT at 90%%",
		Look: []string{"smartctl -a /dev/sda"}, Fix: []string{"free up space"},
	}
	out := captureStdout(t, func() { printTopic(topic, output.ModePlain) })
	if !strings.Contains(out, "Disk Health") || !strings.Contains(out, "SMART + filesystem usage") {
		t.Errorf("the topic title and summary should be shown, got:\n%s", out)
	}
	if !strings.Contains(out, "smartctl -a /dev/sda") {
		t.Errorf("investigate commands should be listed, got:\n%s", out)
	}
	if !strings.Contains(out, "free up space") {
		t.Errorf("fix steps should be listed, got:\n%s", out)
	}
}

func TestExplainAll(t *testing.T) {
	out := captureStdout(t, func() { _ = explainAll(output.ModePlain) })
	topics := explain.Topics()
	if len(topics) == 0 {
		t.Skip("no topics available")
	}
	if !strings.Contains(out, topics[0].Title) {
		t.Errorf("explainAll should render every topic's detail, got missing %q in:\n%s", topics[0].Title, out)
	}
}

// TestExplainAll_HumanMode covers the styled (lipgloss-dim) separator branch
// between topics, only reachable with ModeHuman and 2+ topics — neither the
// ModePlain nor ModeJSON cases above exercise it.
func TestExplainAll_HumanMode(t *testing.T) {
	topics := explain.Topics()
	if len(topics) < 2 {
		t.Skip("need at least 2 topics to exercise the inter-topic separator")
	}
	out := captureStdout(t, func() {
		if err := explainAll(output.ModeHuman); err != nil {
			t.Fatalf("explainAll (human): %v", err)
		}
	})
	if !strings.Contains(out, topics[1].Title) {
		t.Errorf("human mode should still render every topic's detail, got missing %q in:\n%s", topics[1].Title, out)
	}
}

// TestExplainList_HumanMode covers the styled (lipgloss-bold) branch of
// explainList not exercised by the --plain golden test above.
func TestExplainList_HumanMode(t *testing.T) {
	out := captureStdout(t, func() {
		if err := explainList(output.ModeHuman); err != nil {
			t.Fatalf("explainList (human): %v", err)
		}
	})
	if !strings.Contains(out, "dsd explain <topic>") {
		t.Errorf("human mode should still list topics, got:\n%s", out)
	}
}

// TestExplainList_JSONMode covers explainList's structured-output branch.
func TestExplainList_JSONMode(t *testing.T) {
	out := captureStdout(t, func() {
		if err := explainList(output.ModeJSON); err != nil {
			t.Fatalf("explainList (json): %v", err)
		}
	})
	if !strings.Contains(out, `"key"`) {
		t.Errorf("json mode should emit the topic list as JSON, got:\n%s", out)
	}
}

// TestExplainAll_JSONMode covers explainAll's structured-output branch (same
// JSON array as explainList, per its doc comment).
func TestExplainAll_JSONMode(t *testing.T) {
	out := captureStdout(t, func() {
		if err := explainAll(output.ModeJSON); err != nil {
			t.Fatalf("explainAll (json): %v", err)
		}
	})
	if !strings.Contains(out, `"key"`) {
		t.Errorf("json mode should emit topics as JSON, got:\n%s", out)
	}
}

// TestExplainSearch_HumanAndJSONModes covers explainSearch's styled-heading
// branch and its structured-output branch, neither exercised by the --plain
// golden tests above.
func TestExplainSearch_HumanAndJSONModes(t *testing.T) {
	topics := explain.Topics()
	if len(topics) == 0 {
		t.Skip("no topics available")
	}
	human := captureStdout(t, func() {
		if err := explainSearch(topics[0].Key, output.ModeHuman); err != nil {
			t.Fatalf("explainSearch (human): %v", err)
		}
	})
	if !strings.Contains(human, topics[0].Key) {
		t.Errorf("human mode should surface the matching topic, got:\n%s", human)
	}

	jsonOut := captureStdout(t, func() {
		if err := explainSearch(topics[0].Key, output.ModeJSON); err != nil {
			t.Fatalf("explainSearch (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, `"key"`) {
		t.Errorf("json mode should emit hits as JSON, got:\n%s", jsonOut)
	}
}
