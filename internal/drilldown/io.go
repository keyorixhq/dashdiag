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
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TopProcessesByIO returns the top n processes by I/O bytes/sec.
// Returns nil on macOS where /proc/PID/io is not available.
func TopProcessesByIO(ctx context.Context, n int) (*models.Details, error) {
	if runtime.GOOS == "darwin" {
		return &models.Details{
			Type:  "kv_table",
			Title: "Per-process I/O attribution",
			Note:  "Per-process I/O attribution not available on macOS without sudo + fs_usage.",
		}, nil
	}
	return topProcessesByIOLinux(ctx, n)
}

type procIOSample struct {
	pid        int
	name       string
	readBytes  uint64
	writeBytes uint64
}

func readProcIO(pid int) (readBytes, writeBytes uint64, err error) {
	path := filepath.Join("/proc", fmt.Sprintf("%d", pid), "io")
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "read_bytes:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				readBytes, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		case strings.HasPrefix(line, "write_bytes:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				writeBytes, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
	}
	return readBytes, writeBytes, nil
}

func sampleAllProcIO(ctx context.Context) map[int]procIOSample {
	var mu sync.Mutex
	result := make(map[int]procIOSample)

	_ = walkProcs(ctx, func(pid int) error {
		r, w, err := readProcIO(pid)
		if err != nil {
			return nil
		}
		name := procComm(pid)
		mu.Lock()
		result[pid] = procIOSample{pid: pid, name: name, readBytes: r, writeBytes: w}
		mu.Unlock()
		return nil
	})
	return result
}

func topProcessesByIOLinux(ctx context.Context, n int) (*models.Details, error) {
	s0 := sampleAllProcIO(ctx)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(500 * time.Millisecond):
	}
	s1 := sampleAllProcIO(ctx)

	type ioEntry struct {
		pid      int
		name     string
		readBps  float64
		writeBps float64
		totalBps float64
	}
	var entries []ioEntry
	for pid, p1 := range s1 {
		p0, ok := s0[pid]
		if !ok {
			continue
		}
		readBps := float64(p1.readBytes-p0.readBytes) / 0.5
		writeBps := float64(p1.writeBytes-p0.writeBytes) / 0.5
		total := readBps + writeBps
		if total > 0 {
			entries = append(entries, ioEntry{
				pid: pid, name: p1.name,
				readBps: readBps, writeBps: writeBps, totalBps: total,
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].totalBps > entries[j].totalBps })
	if len(entries) > n {
		entries = entries[:n]
	}

	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, []string{
			fmt.Sprintf("%d", e.pid),
			formatBytes(int64(e.readBps)) + "/s",
			formatBytes(int64(e.writeBps)) + "/s",
			e.name,
		})
	}

	d := &models.Details{
		Type:    "process_table",
		Title:   "Top processes by I/O",
		Columns: []string{"PID", "READ/s", "WRITE/s", "COMMAND"},
		Rows:    rows,
	}
	if len(rows) == 0 {
		d.Note = "no active I/O detected in sampling window"
	}
	return d, nil
}
