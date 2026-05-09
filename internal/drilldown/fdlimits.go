package drilldown

import (
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

// TopProcessesByFDPercent returns the top n processes by file descriptor usage %.
func TopProcessesByFDPercent(ctx context.Context, n int) (*models.Details, error) {
	if runtime.GOOS == "darwin" {
		return topProcessesByFDMac(ctx, n)
	}
	return topProcessesByFDLinux(ctx, n)
}

type fdEntry struct {
	pid     int
	name    string
	open    int
	limit   int
	usedPct float64
}

func topProcessesByFDLinux(ctx context.Context, n int) (*models.Details, error) {
	var mu sync.Mutex
	var entries []fdEntry
	partial := false

	err := walkProcs(ctx, func(pid int) error {
		fdPath := filepath.Join("/proc", fmt.Sprintf("%d", pid), "fd")
		fds, err := os.ReadDir(fdPath)
		if os.IsPermission(err) {
			mu.Lock()
			partial = true
			mu.Unlock()
			return nil
		}
		if err != nil {
			return nil
		}
		open := len(fds)
		limit := fdSoftLimit(pid)
		if limit <= 0 {
			return nil
		}
		pct := float64(open) / float64(limit) * 100
		name := procComm(pid)
		mu.Lock()
		entries = append(entries, fdEntry{pid: pid, name: name, open: open, limit: limit, usedPct: pct})
		mu.Unlock()
		return nil
	})
	if err != nil && len(entries) == 0 {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].usedPct > entries[j].usedPct })
	if len(entries) > n {
		entries = entries[:n]
	}

	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, []string{
			fmt.Sprintf("%d", e.pid),
			fmt.Sprintf("%d", e.open),
			fmt.Sprintf("%d", e.limit),
			fmt.Sprintf("%.0f%%", e.usedPct),
			e.name,
		})
	}

	d := &models.Details{
		Type:    "process_table",
		Title:   "Top processes by FD usage",
		Columns: []string{"PID", "OPEN", "LIMIT", "USED%", "COMMAND"},
		Rows:    rows,
	}
	if partial {
		d.Note = "some processes hidden — run as root for full visibility"
	}
	return d, nil
}

// fdSoftLimit reads the soft limit for open files from /proc/PID/limits.
func fdSoftLimit(pid int) int {
	data, err := os.ReadFile(filepath.Join("/proc", fmt.Sprintf("%d", pid), "limits"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "open files") {
			continue
		}
		fields := strings.Fields(line)
		// "Max open files   1024   4096   files"
		// fields: [Max, open, files, softLimit, hardLimit, ...]
		if len(fields) < 4 {
			continue
		}
		v, _ := strconv.Atoi(fields[3])
		return v
	}
	return 0
}

func topProcessesByFDMac(ctx context.Context, n int) (*models.Details, error) {
	out, err := runCmd(ctx, "lsof", "-n", "-P", "-F", "pn")
	if err != nil {
		return nil, err
	}

	// Parse lsof field output: p<pid>\nn<name>
	pidCounts := make(map[string]int)
	var curPID string
	for _, line := range strings.Split(out, "\n") {
		if len(line) == 0 {
			continue
		}
		switch line[0] {
		case 'p':
			curPID = line[1:]
		case 'n':
			if curPID != "" {
				pidCounts[curPID]++
			}
		}
	}

	type pidCount struct {
		pid   string
		count int
	}
	var sorted []pidCount
	for pid, cnt := range pidCounts {
		sorted = append(sorted, pidCount{pid, cnt})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].count > sorted[j].count })
	if len(sorted) > n {
		sorted = sorted[:n]
	}

	rows := make([][]string, 0, len(sorted))
	for _, e := range sorted {
		name := ""
		out2, err2 := runCmd(ctx, "ps", "-p", e.pid, "-o", "comm=")
		if err2 == nil {
			name = strings.TrimSpace(out2)
		}
		rows = append(rows, []string{e.pid, fmt.Sprintf("%d", e.count), name})
	}
	return &models.Details{
		Type:    "process_table",
		Title:   "Top processes by open file count",
		Columns: []string{"PID", "OPEN_FDS", "COMMAND"},
		Rows:    rows,
	}, nil
}
