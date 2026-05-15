package output

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/platform"
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
		sysLabel := platform.SystemLabel()
		line := fmt.Sprintf("%s — %s", p.label, sysLabel)
		sublineRaw := fmt.Sprintf("read only checks, usually under %ds", int(p.estimate.Seconds()))
		subline := fmt.Sprintf("\033[2m%s\033[0m", sublineRaw)
		width := len(line)
		if len(sublineRaw) > width {
			width = len(sublineRaw)
		}
		if width < 56 {
			width = 56
		}
		fmt.Fprintln(os.Stderr, line)
		fmt.Fprintln(os.Stderr, subline)
		fmt.Fprintln(os.Stderr, strings.Repeat("─", width))
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
