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
