package drilldown

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// TCPStateAttribution returns a breakdown of TCP connection states with
// per-process attribution for anomalous patterns.
func TCPStateAttribution(ctx context.Context, results []runner.Result) (*models.Details, error) {
	if runtime.GOOS == "darwin" {
		return tcpStatesMac(ctx)
	}
	return tcpStatesLinux(ctx)
}

func tcpStatesLinux(ctx context.Context) (*models.Details, error) {
	// Try ss first; fall back to /proc/net/tcp
	out, err := runCmd(ctx, "ss", "-tnp", "--no-header")
	if err == nil {
		return parseSsOutput(out), nil
	}
	return parseProcNetTCP(ctx)
}

// parseSsOutput parses `ss -tnp --no-header` output.
func parseSsOutput(out string) *models.Details {
	stateCounts := make(map[string]int)
	procClose := make(map[string]int) // "name[pid]" → CLOSE_WAIT count
	procTime := make(map[string]int)  // "name[pid]" → TIME_WAIT count

	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		state := normalizeSSState(fields[0])
		stateCounts[state]++

		// Process info is last field: users:(("nginx",pid=1234,fd=5))
		proc := ""
		for _, f := range fields {
			if strings.HasPrefix(f, "users:") {
				proc = parseSSProc(f)
				break
			}
		}

		switch state {
		case "CLOSE-WAIT":
			if proc != "" {
				procClose[proc]++
			}
		case "TIME-WAIT":
			if proc != "" {
				procTime[proc]++
			}
		}
	}

	kv := make(map[string]string)
	for state, count := range stateCounts {
		if count > 0 {
			kv[state] = fmt.Sprintf("%d", count)
		}
	}

	var rows [][]string
	// Top CLOSE_WAIT processes
	type procCount struct {
		name  string
		count int
	}
	cwProcs := make([]procCount, 0, len(procClose))
	for name, cnt := range procClose {
		cwProcs = append(cwProcs, procCount{name, cnt})
	}
	sort.Slice(cwProcs, func(i, j int) bool { return cwProcs[i].count > cwProcs[j].count })
	for i, p := range cwProcs {
		if i >= 5 {
			break
		}
		rows = append(rows, []string{p.name, "CLOSE_WAIT", fmt.Sprintf("%d", p.count)})
	}

	twProcs := make([]procCount, 0, len(procTime))
	for name, cnt := range procTime {
		twProcs = append(twProcs, procCount{name, cnt})
	}
	sort.Slice(twProcs, func(i, j int) bool { return twProcs[i].count > twProcs[j].count })
	for i, p := range twProcs {
		if i >= 5 {
			break
		}
		rows = append(rows, []string{p.name, "TIME_WAIT", fmt.Sprintf("%d", p.count)})
	}

	d := &models.Details{
		Type:    "tcp_states",
		Title:   "TCP connection state summary",
		Columns: []string{"PROCESS", "STATE", "COUNT"},
		Rows:    rows,
		KV:      kv,
	}
	return d
}

func normalizeSSState(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, "_", "-"))
}

func parseSSProc(users string) string {
	// users:(("nginx",pid=1234,fd=5))
	start := strings.Index(users, "((\"")
	if start < 0 {
		return ""
	}
	rest := users[start+3:]
	end := strings.Index(rest, "\"")
	if end < 0 {
		return ""
	}
	name := rest[:end]
	pidStart := strings.Index(rest, "pid=")
	if pidStart < 0 {
		return name
	}
	pidStr := rest[pidStart+4:]
	pidEnd := strings.IndexAny(pidStr, ",)")
	if pidEnd > 0 {
		pidStr = pidStr[:pidEnd]
	}
	return fmt.Sprintf("%s[%s]", name, pidStr)
}

// parseProcNetTCP falls back to /proc/net/tcp when ss is unavailable.
func parseProcNetTCP(ctx context.Context) (*models.Details, error) {
	states := map[string]int{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			stateHex := fields[3]
			stateNum, err := strconv.ParseInt(stateHex, 16, 64)
			if err != nil {
				continue
			}
			states[tcpStateName(int(stateNum))]++
		}
		f.Close()
	}

	kv := make(map[string]string)
	for s, c := range states {
		if c > 0 {
			kv[s] = fmt.Sprintf("%d", c)
		}
	}
	return &models.Details{
		Type:  "tcp_states",
		Title: "TCP connection state summary",
		KV:    kv,
		Note:  "per-process attribution requires ss or root access",
	}, nil
}

func tcpStateName(n int) string {
	names := map[int]string{
		1: "ESTABLISHED", 2: "SYN-SENT", 3: "SYN-RECV",
		4: "FIN-WAIT-1", 5: "FIN-WAIT-2", 6: "TIME-WAIT",
		7: "CLOSE", 8: "CLOSE-WAIT", 9: "LAST-ACK",
		10: "LISTEN", 11: "CLOSING",
	}
	if s, ok := names[n]; ok {
		return s
	}
	return fmt.Sprintf("STATE-%d", n)
}

func tcpStatesMac(ctx context.Context) (*models.Details, error) {
	out, err := runCmd(ctx, "netstat", "-an", "-p", "tcp")
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		if fields[0] != "tcp4" && fields[0] != "tcp6" {
			continue
		}
		state := fields[5]
		counts[state]++
	}
	kv := make(map[string]string)
	for s, c := range counts {
		if c > 0 {
			kv[s] = fmt.Sprintf("%d", c)
		}
	}
	return &models.Details{
		Type:  "tcp_states",
		Title: "TCP connection state summary",
		KV:    kv,
	}, nil
}
