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
	var d *models.Details
	var err error
	if runtime.GOOS == "darwin" {
		d, err = topProcessesByRSSMac(ctx, n)
	} else {
		d, err = topProcessesByRSSLinux(ctx, n)
	}
	// Name comes from /proc/PID/status's Name: field (or ps comm on macOS),
	// both attacker-settable via prctl(PR_SET_NAME) — strip control/ANSI-escape
	// bytes before this reaches a rendered table.
	return sanitizeDetails(d), err
}

type procMem struct {
	pid  int
	name string
	rss  int64 // kilobytes from /proc/PID/status
}

func topProcessesByRSSLinux(ctx context.Context, n int) (*models.Details, error) {
	return topProcessesByRSSLinuxAt(ctx, n, "/proc")
}

func topProcessesByRSSLinuxAt(ctx context.Context, n int, procRoot string) (*models.Details, error) {
	var mu sync.Mutex
	var procs []procMem
	partial := false

	totalKB := systemTotalMemKB(procRoot)

	err := walkProcs(ctx, procRoot, func(pid int) error {
		path := filepath.Join(procRoot, fmt.Sprintf("%d", pid), "status")
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

	d := &models.Details{
		Type:    tableProcesses,
		Title:   "Top processes by memory (RSS)",
		Columns: []string{"PID", "MEM%", "RSS", "COMMAND"},
		Rows:    rows,
	}
	if partial {
		d.Note = "some processes hidden — run as root for full visibility"
	}
	return d, nil
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
		pid, mem := fields[0], fields[1]+"%"
		rssBytes, _ := strconv.ParseInt(fields[2], 10, 64)
		rss := formatBytes(rssBytes * 1024)
		cmd := shortenProcessName(strings.Join(fields[3:], " "))
		rows = append(rows, []string{pid, mem, rss, cmd})
	}

	return &models.Details{
		Type:    tableProcesses,
		Title:   "Top processes by memory (RSS)",
		Columns: []string{"PID", "MEM%", "RSS", "COMMAND"},
		Rows:    rows,
	}, nil
}

// systemTotalMemKB reads total system memory from procRoot/meminfo.
func systemTotalMemKB(procRoot string) int64 {
	f, err := os.Open(filepath.Join(procRoot, "meminfo"))
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

// shortenProcessName converts a full binary path to a readable short name.
//
// macOS ps -comm returns full paths like:
//
//	/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
//	/System/Library/Frameworks/CoreServices.framework/.../mds_stores
//
// Rules:
//  1. For .app bundles: extract the app name + executable leaf
//     "/Applications/Foo.app/.../Foo Helper" → "Foo Helper (Foo.app)"
//  2. For system frameworks: just use the basename
//  3. Truncate anything over 40 chars
func shortenProcessName(cmd string) string {
	if cmd == "" {
		return cmd
	}

	// Find if path contains a .app bundle
	if before, after, ok := strings.Cut(cmd, ".app/"); ok {
		// Get the app name (last path component before .app)
		appPath := before
		appName := filepath.Base(appPath) // e.g. "Google Chrome"

		// Get the executable leaf after the .app/
		rest := after               // after ".app/"
		leaf := filepath.Base(rest) // e.g. "Google Chrome Helper (Renderer)"

		// If leaf == appName, just show the app name
		if leaf == appName {
			return truncate40(appName)
		}
		// Otherwise show "Leaf (App.app)"
		return truncate40(leaf + " (" + appName + ".app)")
	}

	// No .app bundle — just use the basename
	return truncate40(filepath.Base(cmd))
}

func truncate40(s string) string {
	const max = 40
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
