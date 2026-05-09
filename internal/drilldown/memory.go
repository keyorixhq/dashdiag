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

// TopProcessesByRSS returns the top n processes sorted by RSS.
func TopProcessesByRSS(ctx context.Context, n int) (*models.Details, error) {
	if runtime.GOOS == "darwin" {
		return topProcessesByRSSMac(ctx, n)
	}
	return topProcessesByRSSLinux(ctx, n)
}

type procMem struct {
	pid  int
	name string
	rss  int64 // kilobytes from /proc/PID/status
}

func topProcessesByRSSLinux(ctx context.Context, n int) (*models.Details, error) {
	var mu sync.Mutex
	var procs []procMem

	totalKB := systemTotalMemKB()

	err := walkProcs(ctx, func(pid int) error {
		path := filepath.Join("/proc", fmt.Sprintf("%d", pid), "status")
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		var name string
		var rssKB int64
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "Name:"):
				name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			case strings.HasPrefix(line, "VmRSS:"):
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					rssKB, _ = strconv.ParseInt(fields[1], 10, 64)
				}
			}
		}
		if rssKB > 0 {
			mu.Lock()
			procs = append(procs, procMem{pid: pid, name: name, rss: rssKB})
			mu.Unlock()
		}
		return nil
	})
	if err != nil && len(procs) == 0 {
		return nil, err
	}

	sort.Slice(procs, func(i, j int) bool { return procs[i].rss > procs[j].rss })
	if len(procs) > n {
		procs = procs[:n]
	}

	rows := make([][]string, 0, len(procs))
	for _, p := range procs {
		memPct := ""
		if totalKB > 0 {
			memPct = fmt.Sprintf("%.1f%%", float64(p.rss)/float64(totalKB)*100)
		}
		rows = append(rows, []string{
			fmt.Sprintf("%d", p.pid),
			memPct,
			formatBytes(p.rss * 1024),
			p.name,
		})
	}

	return &models.Details{
		Type:    "process_table",
		Title:   "Top processes by memory (RSS)",
		Columns: []string{"PID", "MEM%", "RSS", "COMMAND"},
		Rows:    rows,
	}, nil
}

func topProcessesByRSSMac(ctx context.Context, n int) (*models.Details, error) {
	out, err := runCmd(ctx, "ps", "-axro", "pid,pmem,rss,comm")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	rows := make([][]string, 0, n)
	for _, line := range lines[1:] { // skip header
		if len(rows) >= n {
			break
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, mem, cmd := fields[0], fields[1]+"%", strings.Join(fields[3:], " ")
		rssBytes, _ := strconv.ParseInt(fields[2], 10, 64)
		rss := formatBytes(rssBytes * 1024)
		rows = append(rows, []string{pid, mem, rss, cmd})
	}

	return &models.Details{
		Type:    "process_table",
		Title:   "Top processes by memory (RSS)",
		Columns: []string{"PID", "MEM%", "RSS", "COMMAND"},
		Rows:    rows,
	}, nil
}

// systemTotalMemKB reads total system memory from /proc/meminfo.
func systemTotalMemKB() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.ParseInt(fields[1], 10, 64)
				return v
			}
		}
	}
	return 0
}
