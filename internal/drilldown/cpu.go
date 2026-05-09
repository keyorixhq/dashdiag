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
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TopProcessesByCPU returns the top n processes sorted by CPU usage %.
func TopProcessesByCPU(ctx context.Context, n int) (*models.Details, error) {
	if runtime.GOOS == "darwin" {
		return topProcessesByCPUMac(ctx, n)
	}
	return topProcessesByCPULinux(ctx, n)
}

type procCPUSample struct {
	pid      int
	name     string
	cpuTicks uint64 // utime + stime
}

func topProcessesByCPULinux(ctx context.Context, n int) (*models.Details, error) {
	sample := func() (map[int]procCPUSample, uint64) {
		var mu sync.Mutex
		samples := make(map[int]procCPUSample)

		_ = walkProcs(ctx, func(pid int) error {
			path := filepath.Join("/proc", fmt.Sprintf("%d", pid), "stat")
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			fields := strings.Fields(string(data))
			if len(fields) < 15 {
				return nil
			}
			// comm is field 1 (may contain spaces, wrapped in parens)
			name := strings.Trim(fields[1], "()")
			utime, _ := strconv.ParseUint(fields[13], 10, 64)
			stime, _ := strconv.ParseUint(fields[14], 10, 64)
			mu.Lock()
			samples[pid] = procCPUSample{pid: pid, name: name, cpuTicks: utime + stime}
			mu.Unlock()
			return nil
		})

		// total CPU jiffies from /proc/stat
		totalJiffies := systemTotalJiffies()
		return samples, totalJiffies
	}

	s0, j0 := sample()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(200 * time.Millisecond):
	}
	s1, j1 := sample()

	deltaTotal := j1 - j0
	if deltaTotal == 0 {
		deltaTotal = 1
	}
	numCPU := float64(runtime.NumCPU())

	type cpuEntry struct {
		pid    int
		name   string
		cpuPct float64
	}
	var entries []cpuEntry
	for pid, p1 := range s1 {
		p0, ok := s0[pid]
		if !ok {
			continue
		}
		delta := float64(p1.cpuTicks - p0.cpuTicks)
		pct := delta / float64(deltaTotal) * numCPU * 100
		if pct > 0.01 {
			entries = append(entries, cpuEntry{pid: pid, name: p1.name, cpuPct: pct})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].cpuPct > entries[j].cpuPct })
	if len(entries) > n {
		entries = entries[:n]
	}

	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, []string{
			fmt.Sprintf("%d", e.pid),
			fmt.Sprintf("%.1f%%", e.cpuPct),
			e.name,
		})
	}

	return &models.Details{
		Type:    "process_table",
		Title:   "Top processes by CPU%",
		Columns: []string{"PID", "CPU%", "COMMAND"},
		Rows:    rows,
	}, nil
}

// systemTotalJiffies reads total CPU jiffies from /proc/stat (all CPUs).
func systemTotalJiffies() uint64 {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		var total uint64
		for _, f := range fields[1:] {
			v, _ := strconv.ParseUint(f, 10, 64)
			total += v
		}
		return total
	}
	return 0
}

func topProcessesByCPUMac(ctx context.Context, n int) (*models.Details, error) {
	out, err := runCmd(ctx, "ps", "-axro", "pid,pcpu,comm")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	rows := make([][]string, 0, n)
	for _, line := range lines[1:] {
		if len(rows) >= n {
			break
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, cpu := fields[0], fields[1]+"%"
		cmd := strings.Join(fields[2:], " ")
		rows = append(rows, []string{pid, cpu, cmd})
	}
	return &models.Details{
		Type:    "process_table",
		Title:   "Top processes by CPU%",
		Columns: []string{"PID", "CPU%", "COMMAND"},
		Rows:    rows,
	}, nil
}
