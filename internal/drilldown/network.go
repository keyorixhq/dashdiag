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

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

const (
	ddNetKeyTCPStates   = "tcp_states"
	ddNetLabelTCPStates = "TCP connection state summary"
)

// procAttrNote is the honest caveat shown whenever per-process TCP-state
// attribution may be incomplete because we lack the privilege to see another
// user's socket owner.
const procAttrNote = "per-process attribution requires ss or root access"

// TCPStateAttribution returns a breakdown of TCP connection states with
// per-process attribution for anomalous patterns.
func TCPStateAttribution(ctx context.Context, results []runner.Result) (*models.Details, error) {
	var d *models.Details
	var err error
	if runtime.GOOS == "darwin" {
		d, err = tcpStatesMac(ctx)
	} else {
		d, err = tcpStatesLinux(ctx)
	}
	// parseSSProc extracts the process name from ss's users:(...) field, which
	// is ultimately sourced from /proc/PID/comm and attacker-settable via
	// prctl(PR_SET_NAME) — strip control/ANSI-escape bytes before it reaches
	// the PROCESS column.
	return sanitizeDetails(d), err
}

func tcpStatesLinux(ctx context.Context) (*models.Details, error) {
	// Try ss first; fall back to /proc/net/tcp
	out, err := runCmd(ctx, "ss", "-tnp", "--no-header")
	if err == nil {
		return parseSsOutput(out, os.Geteuid() != 0), nil
	}
	return parseProcNetTCPAt(ctx, "/proc/net")
}

// parseSsOutput parses `ss -tnp --no-header` output. nonRoot must reflect
// whether the caller is running unprivileged: `ss -tnp` only reports the
// `users:(...)` process-owner field for sockets the caller owns, so an
// unprivileged run silently drops other users' connections from the
// per-process CLOSE_WAIT/TIME_WAIT tables with no indication — the same false-
// OK-by-omission the /proc/net/tcp fallback already discloses via its own Note.
func parseSsOutput(out string, nonRoot bool) *models.Details {
	stateCounts := make(map[string]int)
	procClose := make(map[string]int) // "name[pid]" → CLOSE_WAIT count
	procTime := make(map[string]int)  // "name[pid]" → TIME_WAIT count

	for line := range strings.SplitSeq(out, "\n") {
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
		Type:    ddNetKeyTCPStates,
		Title:   ddNetLabelTCPStates,
		Columns: []string{"PROCESS", "STATE", "COUNT"},
		Rows:    rows,
		KV:      kv,
	}
	if nonRoot {
		d.Note = procAttrNote
	}
	return d
}

func normalizeSSState(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, "_", "-"))
}

func parseSSProc(users string) string {
	// users:(("nginx",pid=1234,fd=5))
	_, after, ok := strings.Cut(users, "((\"")
	if !ok {
		return ""
	}
	rest := after
	before0, _, ok0 := strings.Cut(rest, "\"")
	if !ok0 {
		return ""
	}
	name := before0
	_, after1, ok1 := strings.Cut(rest, "pid=")
	if !ok1 {
		return name
	}
	pidStr := after1
	pidEnd := strings.IndexAny(pidStr, ",)")
	if pidEnd > 0 {
		pidStr = pidStr[:pidEnd]
	}
	return fmt.Sprintf("%s[%s]", name, pidStr)
}

// parseProcNetTCPAt falls back to <netRoot>/tcp and <netRoot>/tcp6 when ss is
// unavailable. netRoot is normally "/proc/net"; tests pass a testdata fixture
// directory instead.
func parseProcNetTCPAt(_ context.Context, netRoot string) (*models.Details, error) {
	states := map[string]int{}
	for _, name := range []string{"tcp", "tcp6"} {
		path := filepath.Join(netRoot, name)
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
		Type:  ddNetKeyTCPStates,
		Title: ddNetLabelTCPStates,
		KV:    kv,
		Note:  procAttrNote,
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
	for line := range strings.SplitSeq(out, "\n") {
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
		Type:  ddNetKeyTCPStates,
		Title: ddNetLabelTCPStates,
		KV:    kv,
	}, nil
}
