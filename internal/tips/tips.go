package tips

import (
	"fmt"
	"os"
	"time"

	"github.com/keyorixhq/dashdiag/internal/output"
)

var tips = []struct {
	Message string
	Command string
	Tier    string
}{
	{"See only what changed since your last check", "dsd health --diff", ""},
	{"Get a human-readable narrative of system state", "dsd health --story", ""},
	{"Share a snapshot URL in Slack — no install needed", "dsd health --share", "Free account"},
	{"Generate a pre-filled post-mortem template", "dsd health --post-mortem \"title\"", ""},
	{"Deep network analysis: jitter, bonds, traceroute", "dsd net deep", ""},
	{"Markdown output for GitHub issues and Jira", "dsd health --report", ""},
	{"Compare health across multiple servers", "dsd compare server1 server2", "Team"},
	{"Auto-run dsd on SSH login or before deploys", "dsd hook install", ""},
	{"Monitor for changes every 60 seconds", "dsd health --watch", ""},
	{"Embed a live health badge in your README", "dsd health --badge", "Free account"},
	{"Custom thresholds and service checks", "~/.dsd.yaml", ""},
	{"Run all checks — the complete picture", "dsd full", ""},
}

func MaybePrintTip(state *State, mode output.OutputMode) {
	if !state.TipsEnabled || mode != output.ModeHuman || output.IsPlain(false) {
		return
	}
	today := time.Now().Format("2006-01-02")
	if state.LastTipDate == today {
		return
	}

	idx := state.TipIndex % len(tips)
	tip := tips[idx]
	n := idx + 1

	fmt.Fprintf(os.Stderr, "\n💡 Tip: %s\n", tip.Message)
	fmt.Fprintf(os.Stderr, "   Try: %s\n", tip.Command)
	if tip.Tier != "" {
		fmt.Fprintf(os.Stderr, "   %s\n", output.ProLabel(tip.Tier, mode))
	}
	fmt.Fprintf(os.Stderr, "   Tip %d of %d  |  dsd tips (see all)  |  dsd config set tips off\n",
		n, len(tips))

	state.LastTipDate = today
	state.TipIndex = (idx + 1) % len(tips)
}

func PrintAllTips() {
	fmt.Printf("DashDiag Tips (%d total)\n\n", len(tips))
	for i, tip := range tips {
		fmt.Printf("  %2d. %s\n", i+1, tip.Message)
		fmt.Printf("      Try: %s\n", tip.Command)
		if tip.Tier != "" {
			fmt.Printf("      ◆ %s\n", tip.Tier)
		}
		fmt.Println()
	}
}
