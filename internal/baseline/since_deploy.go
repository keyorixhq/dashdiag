package baseline

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func DetectLastDeployTime() (time.Time, string, error) {
	for _, svc := range []string{
		"nginx", "apache2", "caddy", "postgres", "mysqld",
		"redis", "redis-server", "docker", "containerd", "node", "gunicorn",
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		// subprocess-wrappers-05: locale-force the output before parsing it below
		// (ActiveEnterTimestamp's day/month name is locale-dependent — "Mon" on a
		// non-English host silently fails the time.Parse a few lines down),
		// PATH-trust "systemctl" (dsd routinely runs as root; an untrusted $PATH
		// entry ahead of the real binary is a hijack vector), and force-kill on
		// context cancel — the same three primitives collectors/drilldown use.
		cmd := exec.CommandContext(ctx, source.ResolveTrustedTool("systemctl"), "show", svc, //nolint:gosec // G204: hardcoded binary // NOSONAR
			"--property=ActiveEnterTimestamp", "--value")
		cmd.Env = source.HardenedEnv()
		cmd.WaitDelay = source.ExecWaitDelay
		out, err := cmd.Output()
		cancel()
		if err != nil || strings.TrimSpace(string(out)) == "" {
			continue
		}
		t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", strings.TrimSpace(string(out)))
		if err != nil {
			continue
		}
		return t, svc + ".service restarted", nil
	}

	if t, name, err := newestProcStart(2 * time.Hour); err == nil {
		return t, name + " process started", nil
	}

	if t, err := gitLastCommitTime("."); err == nil {
		return t, "git: last commit", nil
	}

	return time.Time{}, "", fmt.Errorf("no deploy signal found")
}

// gitLastCommitTime reads the last commit's timestamp directly from .git's
// plumbing files, without exec'ing the git binary. Shelling out to `git log`
// here used to be exploitable: git honors a repo-local .git/config
// `[alias] log = "!cmd"`, so an unprivileged user who can write into
// .git/config of whatever directory an operator runs `dsd health
// --since-deploy` from (e.g. a shared/group-writable deploy directory)
// could get arbitrary command execution when that operator — often root,
// right after a deploy — ran the command there. git's dubious-ownership
// check only blocks directories owned by a DIFFERENT user, so a
// group/world-writable directory still owned by the legitimate deploy user
// bypasses it. Reading the plumbing directly sidesteps alias dispatch
// entirely. Only handles loose objects (the common case for a recent
// commit) — returns an error if the tip commit has already been packed
// (e.g. after `git gc`), rather than implementing packfile parsing, since
// this is just one of several best-effort deploy-time signals.
func gitLastCommitTime(start string) (time.Time, error) {
	gitDir, err := findGitDir(start)
	if err != nil {
		return time.Time{}, err
	}
	sha, err := resolveHEAD(gitDir)
	if err != nil {
		return time.Time{}, err
	}
	return readCommitTime(gitDir, sha)
}

// findGitDir walks up from start looking for a ".git" entry — a directory in
// a normal checkout, or a "gitdir: <path>" file in a worktree/submodule.
func findGitDir(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		p := filepath.Join(dir, ".git")
		if fi, statErr := os.Stat(p); statErr == nil {
			if fi.IsDir() {
				return p, nil
			}
			if data, readErr := os.ReadFile(filepath.Clean(p)); readErr == nil { // #nosec G304 -- fixed ".git" filename under a directory we're walking, not user input
				if after, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir: "); ok {
					return after, nil
				}
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no .git directory found above %s", start)
		}
		dir = parent
	}
}

// resolveHEAD returns the commit SHA that HEAD currently points to.
func resolveHEAD(gitDir string) (string, error) {
	head, err := os.ReadFile(filepath.Join(gitDir, "HEAD")) // #nosec G304 -- fixed filename under resolved gitDir
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(head))
	ref, ok := strings.CutPrefix(line, "ref: ")
	if !ok {
		return validateSHA(line) // detached HEAD: HEAD contains the SHA directly
	}
	refPath := filepath.Join(gitDir, filepath.FromSlash(ref))
	if data, readErr := os.ReadFile(filepath.Clean(refPath)); readErr == nil { // #nosec G304 -- ref path is under resolved gitDir, read from HEAD's own "ref: refs/..." line
		return validateSHA(strings.TrimSpace(string(data)))
	}
	// Ref may be packed (common after `git gc`) rather than a loose file.
	return resolvePackedRef(gitDir, ref)
}

func resolvePackedRef(gitDir, ref string) (string, error) {
	data, err := os.ReadFile(filepath.Join(gitDir, "packed-refs")) // #nosec G304 -- fixed filename under resolved gitDir
	if err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == ref {
			return validateSHA(fields[0])
		}
	}
	return "", fmt.Errorf("ref %s not found in packed-refs", ref)
}

// validateSHA rejects anything that isn't a plausible git object hash before
// it's used to build a filesystem path.
func validateSHA(sha string) (string, error) {
	if len(sha) < 4 || len(sha) > 64 {
		return "", fmt.Errorf("implausible sha length: %q", sha)
	}
	for _, c := range sha {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", fmt.Errorf("non-hex sha: %q", sha)
		}
	}
	return sha, nil
}

// readCommitTime reads and decompresses the loose commit object for sha and
// extracts the committer timestamp.
func readCommitTime(gitDir, sha string) (time.Time, error) {
	objPath := filepath.Join(gitDir, "objects", sha[:2], sha[2:])
	f, err := os.Open(filepath.Clean(objPath)) // #nosec G304 -- path built from a hex-validated sha under resolved gitDir
	if err != nil {
		return time.Time{}, fmt.Errorf("commit object not found (possibly packed): %w", err)
	}
	defer func() { _ = f.Close() }()

	zr, err := zlib.NewReader(f)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = zr.Close() }()

	body, err := io.ReadAll(io.LimitReader(zr, 1<<20)) // commit objects are small; cap defensively
	if err != nil {
		return time.Time{}, err
	}
	nul := bytes.IndexByte(body, 0)
	if nul < 0 || !bytes.HasPrefix(body, []byte("commit ")) {
		return time.Time{}, fmt.Errorf("malformed commit object")
	}
	for _, line := range strings.Split(string(body[nul+1:]), "\n") {
		after, ok := strings.CutPrefix(line, "committer ")
		if !ok {
			continue
		}
		fields := strings.Fields(after)
		if len(fields) < 2 {
			continue
		}
		if ts, tsErr := strconv.ParseInt(fields[len(fields)-2], 10, 64); tsErr == nil {
			return time.Unix(ts, 0), nil
		}
	}
	return time.Time{}, fmt.Errorf("no committer line found")
}

func newestProcStart(maxAge time.Duration) (time.Time, string, error) {
	return newestProcStartFrom("/proc/[0-9]*/stat", getBootTime(), maxAge)
}

func newestProcStartFrom(glob string, boot time.Time, maxAge time.Duration) (time.Time, string, error) {
	entries, err := filepath.Glob(glob)
	if err != nil {
		return time.Time{}, "", err
	}
	var newest time.Time
	var newestName string
	for _, entry := range entries {
		f, err := os.Open(filepath.Clean(entry))
		if err != nil {
			continue
		}
		startTime, name, ok := parseProcStart(f, boot)
		_ = f.Close()
		if !ok {
			continue
		}
		age := time.Since(startTime)
		if age > maxAge || age < 0 {
			continue
		}
		if startTime.After(newest) {
			newest = startTime
			newestName = name
		}
	}
	if newest.IsZero() {
		return time.Time{}, "", fmt.Errorf("no recent process")
	}
	return newest, newestName, nil
}

// parseProcStart parses a single /proc/<pid>/stat record, returning the process
// name and its start time (field 22, in clock ticks, offset from boot). ok is
// false if the record is malformed.
func parseProcStart(r io.Reader, boot time.Time) (time.Time, string, bool) {
	data, err := io.ReadAll(r)
	if err != nil {
		return time.Time{}, "", false
	}
	raw := string(data)
	// comm (field 2) is parenthesized but can itself contain spaces (many
	// processes/threads use multi-word names, e.g. "Web Content"). Naively
	// splitting the whole line on whitespace shifts every field after it,
	// silently misparsing starttime instead of failing cleanly. Find the
	// closing paren directly instead — same convention as proc_linux.go's
	// procUptimeSec/procCPUSec.
	lp := strings.Index(raw, "(")
	rp := strings.LastIndex(raw, ")")
	if lp < 0 || rp < lp || rp+2 > len(raw) {
		return time.Time{}, "", false
	}
	name := raw[lp+1 : rp]
	fields := strings.Fields(raw[rp+2:])
	if len(fields) < 20 {
		return time.Time{}, "", false
	}
	startTicks, err := strconv.ParseFloat(fields[19], 64)
	if err != nil {
		return time.Time{}, "", false
	}
	startTime := boot.Add(time.Duration(startTicks/100) * time.Second)
	return startTime, name, true
}

func getBootTime() time.Time {
	return getBootTimeFrom("/proc/stat")
}

func getBootTimeFrom(path string) time.Time {
	f, err := os.Open(path)
	if err != nil {
		return time.Now().Add(-24 * time.Hour)
	}
	defer func() { _ = f.Close() }()
	if bt, ok := parseBootTime(f); ok {
		return bt
	}
	return time.Now().Add(-24 * time.Hour)
}

// parseBootTime extracts the btime (boot epoch, seconds) line from /proc/stat.
// ok is false if no valid btime line is present.
func parseBootTime(r io.Reader) (time.Time, bool) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if after, ok := strings.CutPrefix(scanner.Text(), "btime "); ok {
			ts, err := strconv.ParseInt(strings.TrimSpace(after), 10, 64)
			if err != nil {
				return time.Time{}, false
			}
			return time.Unix(ts, 0), true
		}
	}
	if err := scanner.Err(); err != nil {
		return time.Time{}, false
	}
	return time.Time{}, false
}

func FindBaselineBeforeTime(t time.Time, hostname string) (*Snapshot, error) {
	dir := baselineDir()
	entries, err := filepath.Glob(filepath.Join(dir, SafeHostname(hostname)+"-2*.json"))
	if err != nil || len(entries) == 0 {
		return nil, fmt.Errorf("no baselines found for %s", hostname)
	}
	var best *Snapshot
	var bestTime time.Time
	for _, p := range entries {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if info.ModTime().Before(t) && info.ModTime().After(bestTime) {
			snap, err := LoadBaseline(p)
			if err != nil {
				continue
			}
			best = snap
			bestTime = info.ModTime()
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no baseline found before %s", t.Format(time.RFC3339))
	}
	return best, nil
}

func RunSinceDeployDiff(mode output.OutputMode) error {
	deployTime, signal, err := DetectLastDeployTime()
	if err != nil {
		fmt.Println("info:  No deploy signal detected.")
		fmt.Println("       Run dsd health before your next deploy to enable this check.")
		fmt.Println("       Or: dsd health --diff  to compare against your last run.")
		return nil
	}
	hostname, _ := os.Hostname()
	_, err = FindBaselineBeforeTime(deployTime, hostname)
	if err != nil {
		mins := int(time.Since(deployTime).Minutes())
		fmt.Printf("info:  No pre-deploy baseline found (%s, %d min ago).\n", signal, mins)
		fmt.Println("       Run dsd health before your next deploy to enable this check.")
		return nil
	}
	mins := int(time.Since(deployTime).Minutes())
	fmt.Printf("Changes since last deploy (%s, %d min ago)\n\n", signal, mins)
	return nil
}
