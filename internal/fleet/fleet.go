// Package fleet runs `dsd health` across many hosts over plain SSH and
// aggregates the verdicts. It is the free, local, no-backend half of team mode
// (ADR-0004): it shells out to the system `ssh`/`scp` so it inherits the user's
// ~/.ssh/config, keys, and agent — no daemon, no account, nothing phones home.
package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/keyorixhq/dashdiag/internal/platform"
)

// Options tunes a fleet run.
type Options struct {
	RemoteCmd      string        // command to run on each host (default below)
	BinPath        string        // if set, scp this local binary to each host and run it
	RemoteBinDir   string        // where --bin lands on the remote (default /tmp)
	ConnectTimeout time.Duration // ssh ConnectTimeout
	RunTimeout     time.Duration // per-host overall deadline
	Concurrency    int           // max hosts in flight
	// AcceptNewHostKeys opts in to `-o StrictHostKeyChecking=accept-new`
	// (trust-on-first-use for hosts with no cached key, still reject on
	// change). Default false: fleet does NOT override StrictHostKeyChecking
	// at all, so ssh falls through to the user's own ~/.ssh/config (or its
	// "ask" default, which — combined with the always-on BatchMode=yes —
	// fails closed on an unknown host instead of prompting). Without this,
	// a hardcoded accept-new took precedence over an operator's own stricter
	// ssh_config policy for every run, silently downgrading it (ssh -o flags
	// always win over ssh_config).
	AcceptNewHostKeys bool
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
	Issues    []Issue       `json:"issues,omitempty"` // WARN/CRIT insights, for cross-host aggregation
	Elapsed   time.Duration `json:"-"`
	ElapsedMs int64         `json:"elapsed_ms"`
	// CleanupError is set when --bin was used and the post-run removal of the
	// uploaded remote binary failed — the run's health verdict above is still
	// valid, but the remote may still carry the binary dsd copied there. See
	// docs/product-claim-gaps-2026-09-02.md GAP-1: "no persistent agent" only
	// holds if this is empty.
	CleanupError string `json:"cleanup_error,omitempty"`
}

// Issue is a single WARN/CRIT insight from one host, retained so the fleet can
// group the same problem across hosts (fleet-wide vs outlier).
type Issue struct {
	Check   string `json:"check"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// remoteHealth is the subset of `dsd health --json` we parse.
type remoteHealth struct {
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	// Pointer so we can tell an absent "insights" key (not a dsd health doc —
	// reject) from a present-but-empty one (a clean host — accept). Without this
	// any valid JSON object, including "{}" or a foreign error object, parsed as
	// a healthy/reachable host and hid a genuinely failing remote.
	Insights *[]struct {
		Check   string `json:"check"`
		Level   string `json:"level"`
		Message string `json:"message"`
	} `json:"insights"`
}

// hostLabelRe matches one dot-separated label of a hostname or ~/.ssh/config
// Host alias, or an ssh username: letters, digits, dash, underscore,
// non-empty. Underscore isn't valid in a strict DNS label but is common in
// real Host aliases (an existing, intentionally-accepted case — see
// TestValidateHost_AcceptsLegitimate) and carries none of the risk '/' and a
// bare ':' do, so it stays allowed here.
var hostLabelRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]*$`)

// ValidateHost rejects host tokens that ssh/scp would reinterpret as options,
// or whose shape ssh/scp's own argument grammar could reinterpret in a way
// the operator never intended. This is the primary guard for the fleet host
// trust boundary (docs/THREAT_MODEL.md, "Fleet host validation"): a host
// entry like "-oProxyCommand=..." is parsed by ssh as a flag, yielding local
// command execution from a poisoned hosts list.
//
// The [user@]host form is validated STRUCTURALLY, not by a character
// allowlist — a character class can't express "a colon is fine inside IPv6
// brackets but not as a bare separator," and that gap was a real, reproduced
// defect. scp resolves local-vs-remote by scanning its destination argument
// left-to-right for the first ':'; a '/' before that point forces a LOCAL
// path interpretation regardless of what follows, so a host of "/tmp/evil"
// silently copies the binary onto the orchestrating machine instead of any
// remote host — no network call, no error, just a deploy that quietly went
// nowhere. And because the FIRST ':' wins, a host like
// "attacker.com:/tmp/x" turns "host+\":\"+remotePath" into
// "attacker.com:/tmp/x:/opt/dsd/dsd-fleet" — scp uploads to attacker.com, a
// host the operator never listed, from one poisoned line in a --hosts-file.
// Neither is closeable by allowing or forbidding a single character in
// isolation; only a structural parse of what "one host" is allowed to look
// like closes both without also breaking real IPv6 literals.
func ValidateHost(host string) error {
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if strings.HasPrefix(host, "-") {
		return fmt.Errorf("host %q starts with '-' (would be read as an ssh option)", host)
	}
	if strings.Contains(host, "/") {
		return fmt.Errorf("host %q contains '/' -- scp reads a '/' before the first ':' as a local path, not a remote host", host)
	}

	addr := host
	if i := strings.IndexByte(host, '@'); i >= 0 {
		user := host[:i]
		addr = host[i+1:]
		if !hostLabelRe.MatchString(user) {
			return fmt.Errorf("host %q has an invalid user %q before '@'", host, user)
		}
	}

	if strings.HasPrefix(addr, "[") {
		return validateBracketedIPv6(host, addr)
	}
	if strings.Contains(addr, ":") {
		return fmt.Errorf("host %q contains a bare ':' -- an IPv6 literal must be bracketed, e.g. \"[%s]\"", host, addr)
	}
	if addr == "" {
		return fmt.Errorf("host %q has an empty address after '@'", host)
	}
	for _, label := range strings.Split(addr, ".") {
		if !hostLabelRe.MatchString(label) {
			return fmt.Errorf("host %q is not a valid hostname or IPv4 literal", host)
		}
	}
	return nil
}

// validateBracketedIPv6 checks addr is a well-formed "[ipv6]" or
// "[ipv6%zone]" literal -- the only shape a bare ':' is permitted in, and
// the shape scp itself expects for an IPv6 destination.
func validateBracketedIPv6(host, addr string) error {
	if !strings.HasSuffix(addr, "]") || len(addr) < 3 {
		return fmt.Errorf("host %q has an unterminated '[' -- an IPv6 literal must be fully bracketed", host)
	}
	inner := addr[1 : len(addr)-1]
	parsed, err := netip.ParseAddr(inner)
	if err != nil {
		return fmt.Errorf("host %q is not a valid bracketed IPv6 literal: %w", host, err)
	}
	if !parsed.Is6() {
		return fmt.Errorf("host %q brackets an IPv4 address -- brackets are for IPv6 literals only", host)
	}
	return nil
}

// validateRemoteCmd rejects shell metacharacters that would allow command
// injection on the remote host's shell. The command is passed as a single
// string argument to ssh, which hands it to the remote shell for execution;
// unquoted metacharacters therefore run on the remote host.
func validateRemoteCmd(cmd string) error {
	const forbidden = ";|&`$<>\n\r"
	for _, ch := range forbidden {
		if strings.ContainsRune(cmd, ch) {
			return fmt.Errorf("--remote-cmd contains forbidden shell character %q", ch)
		}
	}
	if strings.Contains(cmd, "$(") {
		return fmt.Errorf("--remote-cmd contains command substitution")
	}
	return nil
}

// Run executes the health command on every host with bounded concurrency and
// returns results in input order. Hosts failing ValidateHost are returned as
// ERROR results without ever reaching ssh/scp. Returns an error immediately
// if --remote-cmd contains shell metacharacters.
func Run(ctx context.Context, hosts []string, opts Options) ([]Result, error) {
	opts = opts.withDefaults()
	if err := validateRemoteCmd(opts.RemoteCmd); err != nil {
		return nil, err
	}
	results := make([]Result, len(hosts))
	sem := make(chan struct{}, opts.Concurrency)
	done := make(chan int, len(hosts))

	for i, h := range hosts {
		go func(idx int, host string) {
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := ValidateHost(host); err != nil {
				results[idx] = Result{Host: host, Reachable: false, Worst: "ERROR", Error: "invalid host: " + err.Error()}
				results[idx].finalize(time.Now())
				done <- idx
				return
			}
			results[idx] = runHost(ctx, host, opts)
			done <- idx
		}(i, h)
	}
	for range hosts {
		<-done
	}
	return results, nil
}

func runHost(ctx context.Context, host string, opts Options) Result {
	start := time.Now()
	res := Result{Host: host, Worst: "ERROR"}

	hctx, cancel := context.WithTimeout(ctx, opts.RunTimeout)
	defer cancel()

	remoteCmd := opts.RemoteCmd
	var remoteBin string
	if opts.BinPath != "" {
		remoteBin = strings.TrimRight(opts.RemoteBinDir, "/") + "/dsd-fleet"
		if err := scp(hctx, opts, opts.BinPath, host, remoteBin); err != nil {
			res.Error = "scp failed: " + firstLine(err.Error())
			res.finalize(start)
			return res
		}
		// RemoteBinDir is a fixed default today ("/tmp" — see withDefaults), never
		// CLI-controlled, so this isn't reachable with attacker input. Quoted
		// anyway as defense-in-depth: sshRun ships remoteCmd as a single string
		// argv to the remote shell, so an unquoted path with a space or shell
		// metacharacter would silently break or inject.
		q := shellQuote(remoteBin)
		remoteCmd = "chmod +x " + q + " && " + q + " health --json"
	}

	out, runErr := sshRun(hctx, opts, host, remoteCmd)

	if remoteBin != "" {
		// The binary landed on the remote via scp above — remove it now,
		// unconditionally, whether the health run above succeeded, returned a
		// WARN/CRIT exit, or failed/timed out. GAP-1
		// (docs/product-claim-gaps-2026-09-02.md): "agentless" only holds if
		// nothing dsd copies to a target outlives the run that put it there.
		// Uses ctx (the caller's outer context), NOT hctx — hctx may already
		// be exhausted by a wedged remote health command, and a slow remote
		// must not also poison the cleanup attempt with an already-expired
		// deadline.
		if err := cleanupRemoteBin(ctx, opts, host, remoteBin); err != nil {
			res.CleanupError = firstLine(err.Error())
		}
	}

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

// cleanupGrace is added to ConnectTimeout for the cleanup ssh call's own
// deadline — "rm -f" runs almost instantly once connected, but the budget
// still needs room for the ssh handshake itself on a slow link.
const cleanupGrace = 5 * time.Second

// cleanupRemoteBin removes the binary uploaded for this run via a fresh SSH
// connection. Best-effort — a host that's gone genuinely unreachable can't be
// cleaned up any more than it could be scanned — but always attempted, and
// its failure is reported (Result.CleanupError), never swallowed.
func cleanupRemoteBin(ctx context.Context, opts Options, host, remoteBin string) error {
	cctx, cancel := context.WithTimeout(ctx, opts.ConnectTimeout+cleanupGrace)
	defer cancel()
	_, err := sshRun(cctx, opts, host, "rm -f "+shellQuote(remoteBin))
	return err
}

// shellQuote wraps s in single quotes for safe use inside a remote shell
// command string, escaping any embedded single quote via the standard
// close-quote/escaped-quote/reopen-quote trick.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// stripControl removes control characters (including ESC, which starts
// ANSI/OSC/DCS terminal escape sequences) from s, leaving printable text
// unchanged. fleet/ has no internal package dependencies of its own, so this
// duplicates the small amount of logic in internal/output.SanitizeControl
// rather than adding a new cross-package import for one helper.
func stripControl(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
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
	// Reject JSON that isn't a dsd health document — without the "insights" key
	// (a foreign error object, an older/renamed schema, or "{}") we have no
	// trustworthy verdict and must treat the host as unreachable, not OK.
	if rh.Insights == nil {
		return false
	}
	// Hostname/Version/each insight's Check/Level/Message come straight from a
	// remote host's `dsd health --json` output — a compromised or malicious
	// host in the fleet controls all of it. Downstream renderers (cmd/fleet.go's
	// table printer, the HTML report builder) truncate and strip newlines but
	// never check for other control bytes such as ESC (0x1B), which begins
	// ANSI/OSC terminal escape sequences — strip them here, at the one place
	// every fleet result is parsed.
	res.Hostname = stripControl(rh.Hostname)
	res.Version = stripControl(rh.Version)
	var firstCrit, firstWarn string
	for _, ins := range *rh.Insights {
		check := stripControl(ins.Check)
		level := stripControl(ins.Level)
		message := stripControl(ins.Message)
		switch ins.Level {
		case "CRIT":
			res.Crit++
			if firstCrit == "" {
				firstCrit = message
			}
			res.Issues = append(res.Issues, Issue{Check: check, Level: level, Message: message})
		case "WARN":
			res.Warn++
			if firstWarn == "" {
				firstWarn = message
			}
			res.Issues = append(res.Issues, Issue{Check: check, Level: level, Message: message})
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

// sshOutputMaxBytes caps how much of a remote command's stdout sshRun will
// buffer. `dsd health --json` output is at most a few MB even on a large
// snapshot; a compromised or misbehaving remote host must not be able to make
// the orchestrating machine buffer unbounded memory just by printing a lot to
// stdout over the SSH session.
const sshOutputMaxBytes = 16 << 20 // 16MiB

// capBuffer accumulates up to limit bytes and silently discards the rest, so
// exec.Cmd's streaming copy can never allocate more than the cap regardless
// of how much the remote/child process writes. Write always reports the full
// slice as consumed and never errors, so a capped writer never aborts the
// command early.
type capBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (w *capBuffer) Write(p []byte) (int, error) {
	if remaining := w.limit - w.buf.Len(); remaining > 0 {
		if remaining < len(p) {
			w.buf.Write(p[:remaining])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil
}

// sshRun runs cmd on host and returns its stdout, capped at sshOutputMaxBytes.
// Mirrors os/exec.Cmd.Output()'s behaviour of populating ExitError.Stderr on a
// non-zero exit (capped at 32KiB there too, matching Output()'s own internal
// limit) but with a bounded stdout buffer instead of Output()'s unbounded one.
func sshRun(ctx context.Context, opts Options, host, cmd string) ([]byte, error) {
	// "--" terminates ssh option parsing so a host that survived validation can
	// never be reinterpreted as a flag; ValidateHost is the primary guard.
	args := append(sshBaseArgs(opts), "--", host, cmd)
	// subprocess-wrappers-08: force-kill after context cancel (RunTimeout),
	// same primitive collectors/baseline/drilldown/init use — without it a
	// wedged ssh (a half-open TCP connection, a server that stops responding
	// mid-session) can outlive ctx's deadline instead of dying with it.
	//
	// Deliberately NOT platform.ResolveTrustedTool'd: unlike dsd's own
	// collectors, "ssh" here must resolve via the operator's own $PATH — dsd
	// routinely runs fleet as a non-root user with a custom SSH client
	// (corporate wrapper scripts, a non-standard install prefix, ProxyCommand
	// setups) and PATH-restricting it would break exactly the "inherits the
	// user's ~/.ssh/config, keys, and agent" design this package exists for
	// (see the package doc comment). Locale forcing is skipped for the same
	// reason it doesn't apply: sshRun's stdout is the REMOTE dsd's JSON
	// output, not text parsed for locale-sensitive words/numbers — ssh's own
	// local locale has no bearing on it.
	c := exec.CommandContext(ctx, "ssh", args...) // NOSONAR — hardcoded binary, PATH lookup is intentional
	c.WaitDelay = platform.ExecWaitDelay
	stdout := &capBuffer{limit: sshOutputMaxBytes}
	stderr := &capBuffer{limit: 32 << 10}
	c.Stdout = stdout
	c.Stderr = stderr
	err := c.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			ee.Stderr = stderr.buf.Bytes()
		}
	}
	return stdout.buf.Bytes(), err
}

// scpDestination builds scp's destination argument, "host:remotePath". This
// is the one place this package must remember scp's own parsing rule (see
// ValidateHost's doc comment for the full exploit shape): scp decides
// local-vs-remote by scanning the argument left-to-right for the first ':',
// and a '/' before that point forces a local-path interpretation regardless
// of what follows. ValidateHost already guarantees every host reaching this
// function contains neither '/' nor a bare (unbracketed) ':', which is what
// makes host+":"+remotePath safe to build literally — this re-check exists
// so a future change to ValidateHost's grammar can't silently reopen that
// gap without a loud, immediate failure right where the unsafe string would
// otherwise get built, instead of a quiet misdirected upload discovered
// later (or never).
func scpDestination(host, remotePath string) (string, error) {
	if strings.Contains(host, "/") {
		return "", fmt.Errorf("internal error: scp destination host %q contains '/' -- ValidateHost should have rejected this", host)
	}
	if !strings.HasPrefix(host, "[") && strings.Contains(host, ":") {
		return "", fmt.Errorf("internal error: scp destination host %q contains a bare ':' -- ValidateHost should have rejected this", host)
	}
	return host + ":" + remotePath, nil
}

func scp(ctx context.Context, opts Options, localPath, host, remotePath string) error {
	dest, err := scpDestination(host, remotePath)
	if err != nil {
		return err
	}
	scpArgs := append([]string{"-q"}, sshBaseArgs(opts)...)
	scpArgs = append(scpArgs, "--", localPath, dest)
	// Same rationale as sshRun above: WaitDelay yes, PATH-trust/locale no —
	// scp must resolve via the operator's own $PATH for the same reason ssh
	// does, and there is no output here to locale-parse at all.
	c := exec.CommandContext(ctx, "scp", scpArgs...) // NOSONAR — hardcoded binary, PATH lookup is intentional
	c.WaitDelay = platform.ExecWaitDelay
	return c.Run()
}

func sshBaseArgs(opts Options) []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=" + seconds(opts.ConnectTimeout),
	}
	if opts.AcceptNewHostKeys {
		// Opt-in only — see the AcceptNewHostKeys doc comment on Options.
		args = append(args, "-o", "StrictHostKeyChecking=accept-new")
	}
	return args
}

func seconds(d time.Duration) string {
	s := max(int(d.Seconds()), 1)
	return strconv.Itoa(s)
}

func firstLine(s string) string {
	if before, _, ok := strings.Cut(s, "\n"); ok {
		return before
	}
	return s
}

// Counts tallies hosts by their worst verdict. Unreachable folds in both
// genuinely unreachable hosts and ones whose remote run errored (Worst=="ERROR")
// — the same bucket the human summary and WorstExitCode treat as CRIT-severity.
type Counts struct {
	OK          int `json:"ok"`
	WARN        int `json:"warn"`
	CRIT        int `json:"crit"`
	Unreachable int `json:"unreachable"`
}

// Summary is the fleet-wide aggregate: the machine contract for dsd fleet --json
// and the single source for the human summary line, so the two never disagree.
// It mirrors dsd health --json's top-level verdict/counts so the same automation
// (`jq .verdict`, `jq .counts.crit`) works against a fleet run.
type Summary struct {
	Verdict  string       `json:"verdict"`   // OK | WARN | CRIT — fleet-wide worst
	ExitCode int          `json:"exit_code"` // matches the process exit code (0/1/2)
	Total    int          `json:"total"`     // number of hosts checked
	Counts   Counts       `json:"counts"`
	Hosts    []Result     `json:"hosts"`            // per-host results, sorted by host
	Issues   []IssueGroup `json:"issues,omitempty"` // WARN/CRIT grouped across hosts (fleet-wide vs outlier)
}

// Summarize rolls per-host results up into the fleet verdict. Hosts are sorted by
// host string so the JSON and the table present the same order. The verdict is
// derived from WorstExitCode so the rollup, the table summary, and the exit code
// can never diverge: any CRIT/unreachable host → CRIT/2, any WARN → WARN/1.
func Summarize(results []Result) Summary {
	s := Summary{Total: len(results), Hosts: SortByHost(results)}
	for _, r := range results {
		switch {
		case !r.Reachable || r.Worst == "ERROR":
			s.Counts.Unreachable++
		case r.Worst == "CRIT":
			s.Counts.CRIT++
		case r.Worst == "WARN":
			s.Counts.WARN++
		default:
			s.Counts.OK++
		}
	}
	s.ExitCode = WorstExitCode(results)
	switch s.ExitCode {
	case 2:
		s.Verdict = "CRIT"
	case 1:
		s.Verdict = "WARN"
	default:
		s.Verdict = "OK"
	}
	s.Issues = AggregateIssues(results)
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

// IssueGroup is the same problem (Check + level + message shape) seen across one
// or more hosts. Scope answers the fleet operator's real question — is this
// systemic or is one box drifting from the rest:
//   - "fleet-wide": a majority of reachable hosts share it (fix once, helps many)
//   - "outlier":    exactly one host has it while the others don't (the odd box)
//   - "common":     several hosts, but not a majority
type IssueGroup struct {
	Check  string   `json:"check"`
	Level  string   `json:"level"`  // CRIT | WARN
	Sample string   `json:"sample"` // a representative message
	Hosts  []string `json:"hosts"`  // hosts exhibiting it, sorted
	Count  int      `json:"count"`
	Scope  string   `json:"scope"` // fleet-wide | common | outlier
}

// maskNumbers collapses runs of digits to a single '#' so the same issue with
// host-specific values ("RAM at 97%", "RAM at 85%") groups as one ("RAM at #%").
func maskNumbers(s string) string {
	var b strings.Builder
	inNum := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			if !inNum {
				b.WriteByte('#')
				inNum = true
			}
			continue
		}
		inNum = false
		b.WriteRune(r)
	}
	return b.String()
}

// scopeRank orders groups for display: fleet-wide first (most leverage), then
// common, then outliers (drift) last.
func scopeRank(scope string) int {
	switch scope {
	case "fleet-wide":
		return 0
	case "common":
		return 1
	default: // outlier
		return 2
	}
}

func classifyScope(count, reachable int) string {
	if reachable <= 1 {
		return "common" // can't tell systemic from drift with a single host
	}
	if count == 1 {
		return "outlier"
	}
	if count*2 > reachable {
		return "fleet-wide"
	}
	return "common"
}

// AggregateIssues groups every host's WARN/CRIT issues by (Check, Level, message
// shape) and classifies each group's scope against the number of reachable
// hosts. Within a host the same issue is counted once. Output is ordered
// fleet-wide → common → outlier, then CRIT before WARN, then most hosts first.
func AggregateIssues(results []Result) []IssueGroup {
	reachable := 0
	for _, r := range results {
		if r.Reachable && r.Worst != "ERROR" {
			reachable++
		}
	}

	type acc struct {
		check, level, sample string
		hosts                map[string]bool
	}
	groups := map[string]*acc{}
	var order []string

	for _, r := range results {
		seen := map[string]bool{}
		for _, iss := range r.Issues {
			key := iss.Check + "|" + iss.Level + "|" + maskNumbers(iss.Message)
			if seen[key] {
				continue
			}
			seen[key] = true
			g, ok := groups[key]
			if !ok {
				g = &acc{check: iss.Check, level: iss.Level, sample: iss.Message, hosts: map[string]bool{}}
				groups[key] = g
				order = append(order, key)
			}
			g.hosts[r.Host] = true
		}
	}

	out := make([]IssueGroup, 0, len(order))
	for _, key := range order {
		g := groups[key]
		hosts := make([]string, 0, len(g.hosts))
		for h := range g.hosts {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		out = append(out, IssueGroup{
			Check: g.check, Level: g.level, Sample: g.sample,
			Hosts: hosts, Count: len(hosts), Scope: classifyScope(len(hosts), reachable),
		})
	}

	levelRank := map[string]int{"CRIT": 0, "WARN": 1}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := scopeRank(out[i].Scope), scopeRank(out[j].Scope); a != b {
			return a < b
		}
		if a, b := levelRank[out[i].Level], levelRank[out[j].Level]; a != b {
			return a < b
		}
		return out[i].Count > out[j].Count
	})
	return out
}
