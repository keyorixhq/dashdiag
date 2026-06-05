// Package fleet runs `dsd health` across many hosts over plain SSH and
// aggregates the verdicts. It is the free, local, no-backend half of team mode
// (ADR-0004): it shells out to the system `ssh`/`scp` so it inherits the user's
// ~/.ssh/config, keys, and agent — no daemon, no account, nothing phones home.
package fleet

import (
	"context"
	"encoding/json"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Options tunes a fleet run.
type Options struct {
	RemoteCmd      string        // command to run on each host (default below)
	BinPath        string        // if set, scp this local binary to each host and run it
	RemoteBinDir   string        // where --bin lands on the remote (default /tmp)
	ConnectTimeout time.Duration // ssh ConnectTimeout
	RunTimeout     time.Duration // per-host overall deadline
	Concurrency    int           // max hosts in flight
}

// Defaults fills unset fields with sane values.
func (o Options) withDefaults() Options {
	if o.RemoteCmd == "" {
		o.RemoteCmd = "dsd health --json"
	}
	if o.RemoteBinDir == "" {
		o.RemoteBinDir = "/tmp"
	}
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = 8 * time.Second
	}
	if o.RunTimeout <= 0 {
		o.RunTimeout = 45 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 8
	}
	return o
}

// Result is one host's outcome.
type Result struct {
	Host      string        `json:"host"`
	Reachable bool          `json:"reachable"`
	Error     string        `json:"error,omitempty"`
	Hostname  string        `json:"hostname,omitempty"` // as reported by remote dsd
	Version   string        `json:"version,omitempty"`
	Worst     string        `json:"worst"` // OK | WARN | CRIT | ERROR
	Crit      int           `json:"crit"`
	Warn      int           `json:"warn"`
	TopIssue  string        `json:"top_issue,omitempty"`
	Elapsed   time.Duration `json:"-"`
	ElapsedMs int64         `json:"elapsed_ms"`
}

// remoteHealth is the subset of `dsd health --json` we parse.
type remoteHealth struct {
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	Insights []struct {
		Check   string `json:"check"`
		Level   string `json:"level"`
		Message string `json:"message"`
	} `json:"insights"`
}

// Run executes the health command on every host with bounded concurrency and
// returns results in input order.
func Run(ctx context.Context, hosts []string, opts Options) []Result {
	opts = opts.withDefaults()
	results := make([]Result, len(hosts))
	sem := make(chan struct{}, opts.Concurrency)
	done := make(chan int, len(hosts))

	for i, h := range hosts {
		go func(idx int, host string) {
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = runHost(ctx, host, opts)
			done <- idx
		}(i, h)
	}
	for range hosts {
		<-done
	}
	return results
}

func runHost(ctx context.Context, host string, opts Options) Result {
	start := time.Now()
	res := Result{Host: host, Worst: "ERROR"}

	hctx, cancel := context.WithTimeout(ctx, opts.RunTimeout)
	defer cancel()

	remoteCmd := opts.RemoteCmd
	if opts.BinPath != "" {
		remoteBin := strings.TrimRight(opts.RemoteBinDir, "/") + "/dsd-fleet"
		if err := scp(hctx, opts, opts.BinPath, host, remoteBin); err != nil {
			res.Error = "scp failed: " + firstLine(err.Error())
			res.finalize(start)
			return res
		}
		remoteCmd = "chmod +x " + remoteBin + " && " + remoteBin + " health --json"
	}

	out, runErr := sshRun(hctx, opts, host, remoteCmd)
	// dsd health exits 1 on WARN and 2 on CRIT by design, so a non-zero exit is
	// NOT a failure — the JSON is still on stdout. Parse it regardless; only a
	// genuine SSH failure (no parseable output) marks the host unreachable.
	if parseHealth(out, &res) {
		res.Reachable = true
		res.finalize(start)
		return res
	}
	res.Reachable = false
	res.Worst = "ERROR"
	res.Error = sshFailureReason(runErr)
	res.finalize(start)
	return res
}

// parseHealth extracts counts and the worst level from remote health JSON.
// Returns false if the output is not parseable health JSON.
func parseHealth(stdout []byte, res *Result) bool {
	// dsd may print a one-line banner before JSON; start at the first '{'.
	if i := strings.IndexByte(string(stdout), '{'); i > 0 {
		stdout = stdout[i:]
	}
	var rh remoteHealth
	if err := json.Unmarshal(stdout, &rh); err != nil {
		return false
	}
	res.Hostname = rh.Hostname
	res.Version = rh.Version
	var firstCrit, firstWarn string
	for _, ins := range rh.Insights {
		switch ins.Level {
		case "CRIT":
			res.Crit++
			if firstCrit == "" {
				firstCrit = ins.Message
			}
		case "WARN":
			res.Warn++
			if firstWarn == "" {
				firstWarn = ins.Message
			}
		}
	}
	switch {
	case res.Crit > 0:
		res.Worst = "CRIT"
		res.TopIssue = firstCrit
	case res.Warn > 0:
		res.Worst = "WARN"
		res.TopIssue = firstWarn
	default:
		res.Worst = "OK"
	}
	return true
}

// sshFailureReason turns an ssh/scp exec error into a concise message, surfacing
// ssh's own stderr (e.g. "Connection refused", "Permission denied") when present.
func sshFailureReason(err error) string {
	if err == nil {
		return "no health output (is dsd installed on the remote?)"
	}
	if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
		return firstLine(strings.TrimSpace(string(ee.Stderr)))
	}
	return firstLine(strings.TrimSpace(err.Error()))
}

func (r *Result) finalize(start time.Time) {
	r.Elapsed = time.Since(start)
	r.ElapsedMs = r.Elapsed.Milliseconds()
}

// sshRun runs cmd on host and returns combined stdout.
func sshRun(ctx context.Context, opts Options, host, cmd string) ([]byte, error) {
	args := append(sshBaseArgs(opts), host, cmd)
	return exec.CommandContext(ctx, "ssh", args...).Output()
}

func scp(ctx context.Context, opts Options, localPath, host, remotePath string) error {
	scpArgs := []string{"-q", "-o", "BatchMode=yes",
		"-o", "ConnectTimeout=" + seconds(opts.ConnectTimeout),
		"-o", "StrictHostKeyChecking=accept-new",
		localPath, host + ":" + remotePath}
	return exec.CommandContext(ctx, "scp", scpArgs...).Run()
}

func sshBaseArgs(opts Options) []string {
	return []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=" + seconds(opts.ConnectTimeout),
		"-o", "StrictHostKeyChecking=accept-new",
	}
}

func seconds(d time.Duration) string {
	s := int(d.Seconds())
	if s < 1 {
		s = 1
	}
	return strconv.Itoa(s)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// WorstExitCode returns the fleet-wide exit code: 2 if any host is CRIT or
// unreachable, 1 if any WARN, else 0.
func WorstExitCode(results []Result) int {
	code := 0
	for _, r := range results {
		switch {
		case r.Worst == "CRIT" || r.Worst == "ERROR" || !r.Reachable:
			return 2
		case r.Worst == "WARN":
			code = 1
		}
	}
	return code
}

// SortByHost returns results sorted by host string (stable display order option).
func SortByHost(results []Result) []Result {
	out := make([]Result, len(results))
	copy(out, results)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}
