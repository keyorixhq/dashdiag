package render

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/output"
)

func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Hour:
		m := int(d.Minutes())
		if m < 1 {
			m = 1
		}
		return fmt.Sprintf("%d min ago", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m > 0 {
			return fmt.Sprintf("%dh %dm ago", h, m)
		}
		return fmt.Sprintf("%dh ago", h)
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

func afterLevel(statusChange string) string {
	parts := strings.SplitN(statusChange, "->", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return "OK"
}

func PrintDiff(before, after *baseline.Snapshot, mode output.OutputMode) error {
	entries := baseline.ComputeDiff(before, after)

	if mode == output.ModeJSON {
		data, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(data)
		return err
	}

	ago := timeAgo(before.Timestamp)

	var changed, unchanged []baseline.DiffEntry
	for _, e := range entries {
		if e.Changed {
			changed = append(changed, e)
		} else {
			unchanged = append(unchanged, e)
		}
	}

	if mode == output.ModeHuman {
		fmt.Fprintln(os.Stdout, StyleBold.Render(
			fmt.Sprintf("⚡ Changes since last run (%s) — %s", ago, before.Hostname)))
	} else {
		fmt.Fprintf(os.Stdout, "Changes since last run (%s) — %s\n", ago, before.Hostname)
	}
	fmt.Fprintln(os.Stdout)

	if len(changed) == 0 {
		msg := "  No changes detected"
		if mode == output.ModeHuman {
			fmt.Fprintln(os.Stdout, StyleDim.Render(msg))
		} else {
			fmt.Fprintln(os.Stdout, msg)
		}
	} else {
		for _, e := range changed {
			name := fmt.Sprintf("  %-12s", e.Name)
			diff := fmt.Sprintf("%s → %s", e.Before, e.After)
			if mode == output.ModeHuman {
				level := afterLevel(e.StatusChange)
				if e.Improved {
					level = "OK"
				}
				fmt.Fprintf(os.Stdout, "%s %s\n", name, styleForStatus(level).Render(diff))
			} else {
				fmt.Fprintf(os.Stdout, "%s %s -> %s\n", name, e.Before, e.After)
			}
		}
	}

	if len(unchanged) > 0 {
		names := make([]string, len(unchanged))
		for i, e := range unchanged {
			names[i] = e.Name
		}
		summary := fmt.Sprintf("Unchanged (%d checks): %s", len(unchanged), strings.Join(names, "  "))
		fmt.Fprintln(os.Stdout)
		if mode == output.ModeHuman {
			fmt.Fprintln(os.Stdout, StyleDim.Render(summary))
		} else {
			fmt.Fprintln(os.Stdout, summary)
		}
	}

	fmt.Fprintln(os.Stdout)
	if mode == output.ModeHuman {
		fmt.Fprintln(os.Stdout, StyleDim.Render("→ Run: dsd health deep for full picture"))
	} else {
		fmt.Fprintln(os.Stdout, "-> Run: dsd health deep for full picture")
	}

	return nil
}
