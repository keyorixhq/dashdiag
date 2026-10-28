package baseline

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func DetectLastDeployTime() (time.Time, string, error) {
	for _, svc := range []string{
		"nginx", "apache2", "caddy", "postgres", "mysqld",
		"redis", "redis-server", "docker", "containerd", "node", "gunicorn",
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		// subprocess-wrappers-05: platform.RunHardened locale-forces the output
		// before parsing it below (ActiveEnterTimestamp's day/month name is
		// locale-dependent — "Mon" on a non-English host silently fails the
		// time.Parse a few lines down), PATH-trusts "systemctl" (dsd routinely
		// runs as root; an untrusted $PATH entry ahead of the real binary is a
		// hijack vector), gives ExecHook a chance to observe/deny (fuzz/test
		// only), and force-kills on context cancel — the same primitive
		// collectors/drilldown use.
		cmd, err := platform.RunHardened(ctx, "systemctl", "show", svc,
			"--property=ActiveEnterTimestamp", "--value")
		if err != nil {
			cancel()
			continue
		}
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
		return t, procStartSignal(name), nil
	}

	if t, err := gitLastCommitTime("."); err == nil {
		return t, "git: last commit", nil
	}

	return time.Time{}, "", fmt.Errorf("no deploy signal found")
}

// procStartSignal formats the "<name> process started" deploy signal.
//
// internal-baseline-01-05: name is the raw /proc/<pid>/stat comm field (field
// 2), fully attacker-controlled — any process can set its own comm to
// arbitrary bytes via prctl(PR_SET_NAME) or argv[0]. This "deploy signal"
// string is printed verbatim by RunSinceDeployDiff below and doesn't flow
// through the models.Insight choke point that sanitizes output elsewhere, so
// strip control/escape bytes here, at the source, before a crafted comm name
// can inject terminal escape sequences into the printed report.
func procStartSignal(name string) string {
	return output.SanitizeControl(name) + " process started"
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
	refPath, err := refFilePath(gitDir, ref)
	if err != nil {
		return "", err
	}
	if data, readErr := os.ReadFile(refPath); readErr == nil {
		return validateSHA(strings.TrimSpace(string(data)))
	}
	// Ref may be packed (common after `git gc`) rather than a loose file.
	return resolvePackedRef(gitDir, ref)
}

// refFilePath maps a symbolic HEAD target to its loose-ref file. ref comes
// from the CONTENT of .git/HEAD, which whoever controls the checkout controls,
// and dsd is often run as root in whatever directory the operator is in, so it
// is validated before it is allowed anywhere near a path: it must be a
// well-formed refs/... name, and the joined path must still lie under gitDir.
// The error deliberately does not quote the ref.
func refFilePath(gitDir, ref string) (string, error) {
	if !validRefName(ref) {
		return "", errMalformedRef(len(ref))
	}
	p := filepath.Join(gitDir, filepath.FromSlash(ref))
	rel, err := filepath.Rel(gitDir, p)
	if err != nil || !filepath.IsLocal(rel) {
		return "", errMalformedRef(len(ref))
	}
	return p, nil
}

// errMalformedRef is the only way this file reports a bad HEAD/ref: attacker-
// controlled bytes are never quoted back, only their length.
func errMalformedRef(n int) error {
	return fmt.Errorf("malformed HEAD/ref (%d bytes)", n)
}

// validRefName reports whether ref is acceptable as a symbolic HEAD target,
// following git's check-ref-format rules plus the stricter requirement that it
// live under refs/ (which also rules out absolute paths and "HEAD"-style
// names). Rejected: any ".." or "." or empty component, components ending in
// ".lock", backslash, control characters, and the characters git forbids in
// refnames (space ~ ^ : ? * [ and "@{").
func validRefName(ref string) bool {
	const maxRefLen = 1024
	if len(ref) <= len("refs/") || len(ref) > maxRefLen || !strings.HasPrefix(ref, "refs/") {
		return false
	}
	if strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.HasSuffix(ref, "/") {
		return false
	}
	for _, r := range ref {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(" ~^:?*[\\", r) {
			return false
		}
	}
	for _, comp := range strings.Split(ref, "/") {
		if comp == "" || comp == "." || strings.HasSuffix(comp, ".lock") {
			return false
		}
	}
	return filepath.IsLocal(filepath.FromSlash(ref))
}

func resolvePackedRef(gitDir, ref string) (string, error) {
	if !validRefName(ref) {
		return "", errMalformedRef(len(ref))
	}
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
	return "", errors.New("ref not found in packed-refs")
}

// validateSHA rejects anything that isn't a plausible git object hash before
// it's used to build a filesystem path. sha is file content (HEAD, a ref file
// or packed-refs), so the error reports only its length, never the bytes.
func validateSHA(sha string) (string, error) {
	if len(sha) < 4 || len(sha) > 64 {
		return "", errMalformedRef(len(sha))
	}
	for _, c := range sha {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", errMalformedRef(len(sha))
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
	// strconv.ParseFloat treats "NaN"/"Inf" as successful parses, not errors —
	// err == nil alone doesn't catch a garbled starttime field, and
	// time.Duration(NaN) or time.Duration(+Inf) is an implementation-defined
	// garbage value, the same float->integer conversion class as the fixed
	// zfs.go parseZFSCount bug (#727). This package can't import collectors'
	// parseFiniteFloat (baseline is not in its importer list), so the check
	// is duplicated inline.
	if err != nil || math.IsNaN(startTicks) || math.IsInf(startTicks, 0) || startTicks < 0 {
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

// errNoBaseline marks "there is no usable baseline", as opposed to "the
// baseline directory could not be read": RunSinceDeployDiff reports the first as
// an info line and propagates the second.
var errNoBaseline = errors.New("no baseline")

func FindBaselineBeforeTime(t time.Time, hostname string) (*Snapshot, error) {
	dir, err := baselineDir()
	if err != nil {
		return nil, fmt.Errorf("resolving baseline dir: %w", err)
	}
	entries, dirUnreadable, err := source.GlobChecked(source.Live{}, filepath.Join(dir, SafeHostname(hostname)+"-2*.json"))
	if dirUnreadable {
		return nil, fmt.Errorf("could not read baseline dir %s", dir)
	}
	if err != nil || len(entries) == 0 {
		return nil, fmt.Errorf("no baselines found for %s: %w", hostname, errNoBaseline)
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
		return nil, fmt.Errorf("no baseline found before %s: %w", t.Format(time.RFC3339), errNoBaseline)
	}
	return best, nil
}

func RunSinceDeployDiff(mode output.OutputMode) error {
	deployTime, signal, err := DetectLastDeployTime()
	if err != nil {
		// DetectLastDeployTime's only error is "no deploy signal found" (every
		// probe it runs that fails is skipped inside it), so this is a normal state.
		fmt.Println("info:  No deploy signal detected.")
		fmt.Println("       Run dsd health before your next deploy to enable this check.")
		fmt.Println("       Or: dsd health --diff  to compare against your last run.")
		return nil //nolint:nilerr // see above: absence of a deploy signal is reported as info, not an error
	}
	return reportSinceDeploy(deployTime, signal)
}

// reportSinceDeploy is RunSinceDeployDiff once a deploy signal is in hand
// (split out so the baseline lookup branches can be tested without one).
func reportSinceDeploy(deployTime time.Time, signal string) error {
	hostname, _ := os.Hostname()
	_, err := FindBaselineBeforeTime(deployTime, hostname)
	if err != nil && !errors.Is(err, errNoBaseline) {
		// The baseline directory could not be resolved or read: we do not know
		// whether a pre-deploy baseline exists, so "none found" would be false.
		return err
	}
	if err != nil {
		mins := int(time.Since(deployTime).Minutes())
		fmt.Printf("info:  No pre-deploy baseline found (%s, %d min ago).\n", signal, mins)
		fmt.Println("       Run dsd health before your next deploy to enable this check.")
		return nil //nolint:nilerr // err is errNoBaseline here (anything else returned above): no baseline is an expected state, reported as info
	}
	mins := int(time.Since(deployTime).Minutes())
	fmt.Printf("Changes since last deploy (%s, %d min ago)\n\n", signal, mins)
	return nil
}
