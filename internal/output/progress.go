package output

import (
	"fmt"
	"os"
	"time"
)

type CommandProgress struct {
	label    string
	estimate time.Duration
	mode     OutputMode
	total    int
	done     int
	start    time.Time
}

func NewCommandProgress(label string, estimate time.Duration, mode OutputMode, total int) *CommandProgress {
	return &CommandProgress{
		label:    label,
		estimate: estimate,
		mode:     mode,
		total:    total,
	}
}

func (p *CommandProgress) Start() {
	p.start = time.Now()
	est := int(p.estimate.Seconds())
	if p.mode == ModeHuman {
		fmt.Fprintf(os.Stderr, "⚡ %s (read-only) — ~%ds\n", p.label, est)
	} else {
		fmt.Fprintf(os.Stderr, "[INFO] %s (read-only) — ~%ds\n", p.label, est)
	}
}

func (p *CommandProgress) Step(collectorName string) {
	p.done++
	if p.mode == ModeHuman {
		pct := 0
		if p.total > 0 {
			pct = (p.done * 100) / p.total
		}
		fmt.Fprintf(os.Stderr, "\r  %s [%d/%d] %d%%   ", collectorName, p.done, p.total, pct)
	} else {
		fmt.Fprintf(os.Stderr, "[INFO] %s\n", collectorName)
	}
}

func (p *CommandProgress) Note(msg string) {
	if p.mode == ModeHuman {
		fmt.Fprintf(os.Stderr, "\n  ℹ  %s\n", msg)
	} else {
		fmt.Fprintf(os.Stderr, "[INFO] %s\n", msg)
	}
}

func (p *CommandProgress) Done() {
	elapsed := time.Since(p.start)
	if p.mode == ModeHuman {
		fmt.Fprintf(os.Stderr, "\r\033[K  done in %.1fs\n", elapsed.Seconds())
	} else {
		fmt.Fprintf(os.Stderr, "[INFO] done in %.1fs\n", elapsed.Seconds())
	}
}
