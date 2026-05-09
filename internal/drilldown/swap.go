package drilldown

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TopProcessesBySwap returns the top n processes sorted by VmSwap usage.
// Returns nil on macOS where per-process swap attribution is not available.
func TopProcessesBySwap(ctx context.Context, n int) (*models.Details, error) {
	if runtime.GOOS == "darwin" {
		return &models.Details{
			Type:  "kv_table",
			Title: "Per-process swap attribution",
			Note:  "macOS does not expose per-process swap attribution. Use top RSS consumers as a proxy.",
		}, nil
	}
	return topProcessesBySwapLinux(ctx, n)
}

type procSwap struct {
	pid    int
	name   string
	swapKB int64
}

func topProcessesBySwapLinux(ctx context.Context, n int) (*models.Details, error) {
	var mu sync.Mutex
	var procs []procSwap
	partial := false

	err := walkProcs(ctx, func(pid int) error {
		path := filepath.Join("/proc", fmt.Sprintf("%d", pid), "status")
		f, err := os.Open(path)
		if os.IsPermission(err) {
			mu.Lock()
			partial = true
			mu.Unlock()
			return nil
		}
		if err != nil {
			return nil
		}
		defer f.Close()

		var name string
		var swapKB int64
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "Name:"):
				name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			case strings.HasPrefix(line, "VmSwap:"):
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					swapKB, _ = strconv.ParseInt(fields[1], 10, 64)
				}
			}
		}
		if swapKB > 0 {
			mu.Lock()
			procs = append(procs, procSwap{pid: pid, name: name, swapKB: swapKB})
			mu.Unlock()
		}
		return nil
	})
	if err != nil && len(procs) == 0 {
		return nil, err
	}

	sort.Slice(procs, func(i, j int) bool { return procs[i].swapKB > procs[j].swapKB })
	if len(procs) > n {
		procs = procs[:n]
	}

	rows := make([][]string, 0, len(procs))
	for _, p := range procs {
		rows = append(rows, []string{
			fmt.Sprintf("%d", p.pid),
			formatBytes(p.swapKB * 1024),
			p.name,
		})
	}

	d := &models.Details{
		Type:    "process_table",
		Title:   "Top processes by swap usage",
		Columns: []string{"PID", "SWAP", "COMMAND"},
		Rows:    rows,
	}
	if partial {
		d.Note = "some processes hidden — run as root for full visibility"
	}
	return d, nil
}
