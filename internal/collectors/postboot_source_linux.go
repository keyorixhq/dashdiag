//go:build linux

package collectors

// postboot_source_linux.go — prior-boot forensics source-availability decision
// tree for the (proposed) PostBoot collector. See the spec entry in BACKLOG.md
// ("Post-unexpected-reboot forensics"). This file is DRAFT scaffolding: the
// source trichotomy and its tests are the load-bearing part; the event-reading
// is deliberately left to reuse parseOOMEvents (oom_linux.go) and the journal/
// dmesg readers (timeline_linux.go) against boot -1 instead of the live boot.
//
// Why this file is only about "can we even look?" and not about what we find:
// post-reboot forensics is the one place where the project's standing
// "not-applicable collectors are omitted, never phantom OK" rule
// (internal/render/json.go, COMPATIBILITY.md §checks[]) is INVERTED. The absence
// of prior-boot data is itself the headline, and must be LOUD, not dropped. An
// empty post-boot panel rendering as OK is exactly the silent-failure class this
// product exists to kill — the same bug already guarded against in oom_linux.go
// (StatusReason "kernel log unreadable") and timeline_linux.go
// (SourcesUnavailable). This collector must carry that honesty across a reboot
// boundary, where the most common failure (volatile journald) means the evidence
// physically no longer exists.
//
// Three states stay distinguishable end to end:
//
//   StateFound        — we can read the prior boot; forensics may then return
//                       findings OR a clean "nothing notable" (ABSENT-at-event-
//                       level, a real healthy result).
//   StateAbsent       — no prior boot exists at all (first boot since journald
//                       began persisting). Real, and not a failure — but the
//                       verdict must say "no prior boot on record", never imply
//                       a clean shutdown we never observed.
//   StateUnmeasurable — we could not look (volatile journald, no privilege,
//                       non-systemd with no wtmp). MUST surface as INFO/WARN,
//                       never as OK, never omitted.

import (
	"context"
	"os"
	"path/filepath"
)

// PostBootSourceKind identifies which prior-boot evidence stream a finding came
// from, so the verdict can state provenance honestly: a finding from the
// persistent journal is stronger than one inferred from a coarse wtmp gap, and
// the kernel ring buffer is CURRENT-boot only and must never back a boot -1
// claim.
type PostBootSourceKind string

const (
	PBSourcePersistentJournal PostBootSourceKind = "persistent_journal" // journalctl --boot=-1, durable across reboot
	PBSourceWtmp              PostBootSourceKind = "wtmp"               // last -x, coarse clean/unclean shutdown
	PBSourceNone              PostBootSourceKind = "none"
)

// PostBootReason explains a non-Found outcome in machine-stable terms. The codes
// (not the hint text) are what the unit tests assert on.
type PostBootReason string

const (
	PBReasonNoPersistentJournal PostBootReason = "no_persistent_journal" // Storage=volatile / no /var/log/journal — prior boot is GONE
	PBReasonJournalUnreadable   PostBootReason = "journal_unreadable"    // exists but EACCES (non-root, not in systemd-journal)
	PBReasonFirstBoot           PostBootReason = "first_boot"            // genuinely no prior boot (StateAbsent)
	PBReasonNonSystemdNoWtmp    PostBootReason = "non_systemd_no_wtmp"   // OpenRC/runit and no wtmp either
)

type PostBootState int

const (
	PBStateFound PostBootState = iota
	PBStateAbsent
	PBStateUnmeasurable
)

// PostBootSourceReport is what assessPostBootSource hands to the forensics layer.
// It is the contract that keeps ABSENT and UNMEASURABLE from collapsing into each
// other — the single most important property of this whole feature.
type PostBootSourceReport struct {
	State      PostBootState
	Primary    PostBootSourceKind // meaningful when State==Found
	Fallbacks  []PostBootSourceKind
	Reason     PostBootReason // set when State != Found, or as an advisory on a downgraded Found
	PriorBoots int            // prior boots journald can see; 0 == only current
}

// persistentJournalDir is the durable journal location. /run/log/journal is
// volatile and is intentionally NOT consulted for cross-boot evidence: its
// presence means this-boot only, and trusting it for boot -1 would be a
// correctness bug (the same class as using dmesg for a prior-boot claim).
const persistentJournalDir = "/var/log/journal"

// pbEnv abstracts every host probe the decision tree makes, so the trichotomy is
// unit-testable against fixtures (volatile-journal host, OpenRC host, non-root
// EACCES, first-boot) with no live machine — mirroring the fixture-driven style
// of the existing collector tests (oom_linux_test.go, timeline_linux_test.go).
type pbEnv struct {
	isSystemd bool
	hasWtmp   bool

	readDir         func(path string) ([]os.DirEntry, error)
	countPriorBoots func(ctx context.Context) (int, error)
}

// assessPostBootSource decides, BEFORE any forensics run, what we are able to
// see. It performs no event parsing — only source discovery — so the expensive
// boot -1 read never runs against a source that cannot answer.
func assessPostBootSource(ctx context.Context, env pbEnv) PostBootSourceReport {
	// 1. OS / init gate. systemd-journald is the only durable cross-boot source.
	//    On OpenRC/runit hosts (Alpine CT210), wtmp is the sole cross-boot
	//    evidence and it's coarse — don't claim journal-grade forensics we can't
	//    deliver; if there's no wtmp either, we're honestly blind.
	if !env.isSystemd {
		if env.hasWtmp {
			return PostBootSourceReport{State: PBStateFound, Primary: PBSourceWtmp}
		}
		return PostBootSourceReport{State: PBStateUnmeasurable, Reason: PBReasonNonSystemdNoWtmp}
	}

	// 2. Persistent journal present AND non-empty? This is the crux. An absent or
	//    empty /var/log/journal means journald is volatile and the prior boot did
	//    NOT survive the reboot — the single most common UNMEASURABLE cause, and
	//    the DEFAULT on many cloud/minimal images. wtmp may still answer the
	//    coarse "was the last shutdown clean" question, so downgrade rather than
	//    go fully dark — but carry the reason so the verdict says "journal-grade
	//    detail unavailable", not a confident clean bill of health.
	if !pbDirHasJournal(env, persistentJournalDir) {
		if env.hasWtmp {
			return PostBootSourceReport{
				State:   PBStateFound,
				Primary: PBSourceWtmp,
				Reason:  PBReasonNoPersistentJournal, // advisory on a downgraded Found
			}
		}
		return PostBootSourceReport{State: PBStateUnmeasurable, Reason: PBReasonNoPersistentJournal}
	}

	// 3. Journal exists — can WE read it? Non-root without systemd-journal group
	//    gets EACCES. That's UNMEASURABLE-by-privilege, NOT absent. (This is why
	//    dual-privilege runs matter: a root run sees boot -1; a non-root run
	//    legitimately reports journal_unreadable; together they're the honest
	//    picture — the same asymmetry already documented in the project's
	//    non-root methodology.)
	priorBoots, err := env.countPriorBoots(ctx)
	if err != nil {
		return PostBootSourceReport{State: PBStateUnmeasurable, Reason: PBReasonJournalUnreadable}
	}
	if priorBoots == 0 {
		// Genuinely first boot on record. ABSENT, not a failure — but flag the
		// reason so the verdict says "no prior boot on record" rather than
		// implying a clean shutdown we never witnessed.
		return PostBootSourceReport{State: PBStateAbsent, Reason: PBReasonFirstBoot}
	}

	return PostBootSourceReport{
		State:      PBStateFound,
		Primary:    PBSourcePersistentJournal,
		Fallbacks:  pbFallbacks(env),
		PriorBoots: priorBoots,
	}
}

// pbFallbacks lists corroborating streams available alongside the primary, so a
// journal finding can be cross-checked (an OOM in boot -1 corroborated by a wtmp
// unclean-shutdown gap). NEVER includes the kernel ring buffer for prior-boot
// claims — dmesg is current-boot only.
func pbFallbacks(env pbEnv) []PostBootSourceKind {
	if env.hasWtmp {
		return []PostBootSourceKind{PBSourceWtmp}
	}
	return nil
}

// pbDirHasJournal reports whether /var/log/journal exists AND holds at least one
// machine subdirectory containing a *.journal file. An empty journal dir
// (created but never written — Storage=auto before first rotation) is NOT
// persistent evidence and must read as volatile, or we'd falsely promise
// cross-boot forensics on a host that has none.
func pbDirHasJournal(env pbEnv, dir string) bool {
	entries, err := env.readDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		inner, err := env.readDir(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		for _, f := range inner {
			if filepath.Ext(f.Name()) == ".journal" {
				return true
			}
		}
	}
	return false
}
