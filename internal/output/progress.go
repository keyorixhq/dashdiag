package output

import (
	"fmt"
	"os"
	"strings"
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
	if p.mode == ModeHuman {
		fmt.Fprintf(os.Stderr, "%s — read only checks, usually under %ds\n", p.label, int(p.estimate.Seconds()))
		fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("─", 56))
	} else {
		fmt.Fprintf(os.Stderr, "[INFO] %s — ~%ds\n", p.label, int(p.estimate.Seconds()))
	}
}

func (p *CommandProgress) Step(_ string) {
	p.done++
	if p.mode != ModeHuman {
		fmt.Fprintf(os.Stderr, "[INFO] step %d/%d\n", p.done, p.total)
	}
}

func (p *CommandProgress) Elapsed() time.Duration {
	return time.Since(p.start)
}

func (p *CommandProgress) Note(msg string) {
	if p.mode == ModeHuman {
		fmt.Fprintf(os.Stderr, "\n  ℹ  %s\n", msg)
	} else {
		fmt.Fprintf(os.Stderr, "[INFO] %s\n", msg)
	}
}

func (p *CommandProgress) Done() {
	if p.mode != ModeHuman {
		fmt.Fprintf(os.Stderr, "[INFO] done in %.1fs\n", p.Elapsed().Seconds())
	}
}
