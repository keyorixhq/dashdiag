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
	var d *models.Details
	var err error
	if runtime.GOOS == "darwin" {
		d, err = topProcessesByCPUMac(ctx, n)
	} else {
		d, err = topProcessesByCPULinux(ctx, n)
	}
	// name comes from /proc/PID/stat's comm field, attacker-settable via
	// prctl(PR_SET_NAME) — strip control/ANSI-escape bytes before this reaches
	// the rendered table.
	return sanitizeDetails(d), err
}

type procCPUSample struct {
	pid       int
	name      string
	cpuTicks  uint64 // utime + stime
	startTime string // /proc/PID/stat field 22 — process-instance identity
}

func topProcessesByCPULinux(ctx context.Context, n int) (*models.Details, error) {
	return topProcessesByCPULinuxAt(ctx, n, "/proc")
}

func topProcessesByCPULinuxAt(ctx context.Context, n int, procRoot string) (*models.Details, error) {
	sample := func() (map[int]procCPUSample, uint64) {
		var mu sync.Mutex
		samples := make(map[int]procCPUSample)

		_ = walkProcs(ctx, procRoot, func(pid int) error {
			path := filepath.Join(procRoot, fmt.Sprintf("%d", pid), "stat")
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			// comm may contain spaces/parens — parse from the last ')' so the
			// utime/stime indices don't shift (e.g. a "Web Content" process).
			name, rest, ok := parseProcStatComm(string(data))
			if !ok || len(rest) < 20 {
				return nil
			}
			utime, _ := strconv.ParseUint(rest[11], 10, 64) // stat field 14
			stime, _ := strconv.ParseUint(rest[12], 10, 64) // stat field 15
			startTime := rest[19]                           // stat field 22 (starttime, in clock ticks since boot)
			mu.Lock()
			samples[pid] = procCPUSample{pid: pid, name: name, cpuTicks: utime + stime, startTime: startTime}
			mu.Unlock()
			return nil
		})

		// total CPU jiffies from procRoot/stat
		totalJiffies := systemTotalJiffies(procRoot)
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
		// PIDs are recycled by the kernel; a PID that exited and was reused by
		// an unrelated process between the two samples must not have its two
		// halves stitched together. /proc/PID/stat's starttime (field 22) is
		// fixed for the lifetime of a process instance, so a mismatch here
		// means s0 and s1 sampled two different processes under the same PID.
		if p1.startTime != p0.startTime {
			continue
		}
		// Skip if the counter went backwards — defends against any remaining
		// clock/counter anomaly even once startTime confirms same-process
		// identity. The unsigned subtraction would otherwise wrap to a huge
		// bogus rate and top the list.
		if p1.cpuTicks < p0.cpuTicks {
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
		Type:    tableProcesses,
		Title:   "Top processes by CPU%",
		Columns: []string{"PID", "CPU%", "COMMAND"},
		Rows:    rows,
	}, nil
}

// systemTotalJiffies reads total CPU jiffies from procRoot/stat (all CPUs).
func systemTotalJiffies(procRoot string) uint64 {
	f, err := os.Open(filepath.Join(procRoot, "stat"))
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
		Type:    tableProcesses,
		Title:   "Top processes by CPU%",
		Columns: []string{"PID", "CPU%", "COMMAND"},
		Rows:    rows,
	}, nil
}
