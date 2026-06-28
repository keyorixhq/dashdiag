//go:build linux

package collectors

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// PostBootCollector answers "what happened to the box across the last reboot, and could
// we even tell?". It first decides what evidence is readable (assessPostBootSource — the
// FOUND/ABSENT/UNMEASURABLE trichotomy), and only then reads the prior boot. The
// expensive boot -1 read never runs against a source that cannot answer. Scope is
// strictly guest-side; reuses the OOM parser against the prior boot rather than the
// current one.
type PostBootCollector struct{}

func NewPostBootCollector() *PostBootCollector      { return &PostBootCollector{} }
func (c *PostBootCollector) Name() string           { return "PostBoot" }
func (c *PostBootCollector) Timeout() time.Duration { return 8 * time.Second }

// PostBootAvailable gates the collector: it can only say anything where there is a
// potential cross-boot source — a journal (journalctl) or wtmp. On a host with neither
// it is genuinely n/a and omitted (the ONE case where omitting is correct).
//
// Skipped in a container: prior-boot forensics are about THIS system's kernel boot,
// but a container shares the host kernel and never reboots independently — its wtmp
// reflects container start/stop and a `pct stop`/SIGKILL teardown reads as an
// "unclean shutdown" that is not a host fault. Found live: freshly-started LXCs
// false-WARNed "the previous shutdown was unclean".
func PostBootAvailable() bool {
	// Hermetic container check: under replay this reflects the CAPTURED host, so a VM
	// capture replayed inside a container still reports prior-boot forensics (#586 class).
	if ContainerContextViaSource().InContainer {
		return false
	}
	return lookPathOK("journalctl") || fileExists("/var/log/wtmp")
}

func (c *PostBootCollector) Collect(ctx context.Context) (interface{}, error) {
	report := assessPostBootSource(ctx, livePostBootEnv(ctx))

	info := &models.PostBootInfo{Available: true, Reason: string(report.Reason)}
	switch report.State {
	case PBStateAbsent:
		info.State = "absent"
	case PBStateUnmeasurable:
		info.State = "unmeasurable"
	case PBStateFound:
		info.State = "found"
		info.Source = string(report.Primary)
		info.PriorBoots = report.PriorBoots
		if report.Primary == PBSourcePersistentJournal {
			readPriorBootJournal(ctx, info)
		} else {
			// Coarse wtmp source — no journal-grade OOM/panic detail; best-effort
			// unclean-shutdown only, left unconfirmed if `last` can't speak to it.
			info.UncleanShutdown, info.ShutdownChecked = priorBootUncleanWtmp(ctx)
		}
	}
	return info, nil
}

// livePostBootEnv builds the host probes the trichotomy needs. isSystemd keys on
// journalctl (the only durable cross-boot source); hasWtmp on the wtmp file.
func livePostBootEnv(ctx context.Context) pbEnv {
	return pbEnv{
		isSystemd:       lookPathOK("journalctl"),
		hasWtmp:         fileExists("/var/log/wtmp"),
		readDir:         readDirEntries,
		countPriorBoots: countPriorBootsLive,
	}
}

// countPriorBootsLive counts boots before the current one via `journalctl --list-boots`.
// Each line is one boot (index 0 == current, -1/-2/... == prior), so prior = lines-1.
// An error (EACCES on the journal) propagates so the trichotomy reports it as
// journal_unreadable rather than "first boot".
func countPriorBootsLive(ctx context.Context) (int, error) {
	out, err := runCmd(ctx, "journalctl", "--list-boots", "--no-pager", "-q")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	if n <= 1 {
		return 0, nil // only the current boot is on record
	}
	return n - 1, nil
}

// ---------- prior-boot (boot -1) journal forensics ----------

// readPriorBootJournal fills the finding fields from the previous boot's journal.
func readPriorBootJournal(ctx context.Context, info *models.PostBootInfo) {
	info.OOMKills, info.OOMVictims = priorBootOOM(ctx)
	info.KernelPanic, info.PanicHint = priorBootPanic(ctx)
	info.UncleanShutdown, info.ShutdownChecked = priorBootUncleanJournal(ctx)
}

// priorBootOOM reuses the OOM parser against the PRIOR boot's kernel log.
func priorBootOOM(ctx context.Context) (kills int, victims []string) {
	out, err := runCmd(ctx, "journalctl", "-k", "--boot=-1", "--no-pager",
		"-o", "short-iso", "--grep", "Out of memory|Killed process")
	if err != nil {
		return 0, nil
	}
	events := parseOOMEvents(out)
	seen := map[string]bool{}
	for _, e := range events {
		if e.Process != "" && !seen[e.Process] {
			seen[e.Process] = true
			victims = append(victims, e.Process)
		}
	}
	if len(victims) > 5 {
		victims = victims[:5]
	}
	return len(events), victims
}

// panicRe matches the fatal kernel signatures (panic, oops, GPF, fatal BUG). Deliberately
// narrow — non-fatal "WARNING:"/"Call Trace" noise is excluded so a routine warning in
// the prior boot is not reported as a crash.
var panicRe = regexp.MustCompile(`Kernel panic|Oops:|general protection fault|BUG: unable to handle|kernel BUG at`)

// priorBootPanic reports whether the prior boot logged a fatal kernel event. Uses
// journalctl's server-side --grep so only matching lines are returned (bounded output,
// no full-boot-log pull).
func priorBootPanic(ctx context.Context) (panicked bool, hint string) {
	out, err := runCmd(ctx, "journalctl", "-k", "--boot=-1", "--no-pager", "-q", "-o", "cat",
		"--grep", "Kernel panic|Oops:|general protection fault|BUG: unable to handle|kernel BUG at")
	if err != nil {
		return false, ""
	}
	for _, line := range strings.Split(out, "\n") {
		if panicRe.MatchString(line) {
			return true, strings.TrimSpace(truncatePanic(line))
		}
	}
	return false, ""
}

func truncatePanic(s string) string {
	const max = 160
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// shutdownMarkerRe matches a recorded systemd shutdown/reboot sequence. Its PRESENCE in
// the tail of the prior boot means the box stopped cleanly; its ABSENCE means it stopped
// without shutting down (power loss / hard reset / panic / host eviction).
var shutdownMarkerRe = regexp.MustCompile(`(?i)reached target.*(shutdown|reboot|power-?off|halt)|systemd-shutdown|powering off|rebooting\.|unmounting |deactivating swap`)

// priorBootUncleanJournal reports whether the prior boot ended without a shutdown
// sequence. It reads a BOUNDED TAIL of boot -1 (the shutdown sequence, if any, is the
// last thing logged) and scans in Go — deliberately NOT `journalctl --grep`, which exits
// non-zero on zero matches and would make the unclean case (no marker) look like an
// unreadable journal. Reached only on the FOUND-via-persistent-journal path, where
// boot -1 is already confirmed readable, so a non-empty tail with no marker is a real
// unclean stop.
func priorBootUncleanJournal(ctx context.Context) (unclean, checked bool) {
	out, err := runCmd(ctx, "journalctl", "--boot=-1", "--no-pager", "-q", "-o", "cat", "-n", "200")
	if err != nil || strings.TrimSpace(out) == "" {
		return false, false
	}
	for _, line := range strings.Split(out, "\n") {
		if shutdownMarkerRe.MatchString(line) {
			return false, true // a clean shutdown/reboot sequence was recorded
		}
	}
	return true, true // tail readable but no shutdown sequence → unclean stop
}

// priorBootUncleanWtmp is the coarse wtmp fallback: `last` records a "crash" pseudo-entry
// when a boot was not preceded by a clean shutdown. checked is false when `last` is
// unavailable (don't claim clean on a read we couldn't do).
func priorBootUncleanWtmp(ctx context.Context) (unclean, checked bool) {
	out, err := runCmd(ctx, "last", "-x", "-n", "20")
	if err != nil {
		return false, false
	}
	return strings.Contains(out, "crash"), true
}
