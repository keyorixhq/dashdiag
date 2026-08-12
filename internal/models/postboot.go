package models

// PostBootInfo is the prior-boot forensic verdict — "what happened to the box across
// the last reboot, and could we even tell?". It deliberately INVERTS the standing
// "omit a not-applicable collector" rule: across a reboot boundary the most common
// outcome is that the evidence physically no longer exists (volatile journald), and
// that absence is the headline finding, so State is always reported, never dropped.
//
// State is one of:
//
//	"found"        — we could read the prior boot; the finding fields below are
//	                 meaningful (and may legitimately all be clean).
//	"absent"       — no prior boot on record (first boot since journald began
//	                 persisting). Real, not a failure.
//	"unmeasurable" — we could NOT look (volatile journald / EACCES / non-systemd with
//	                 no wtmp). Surfaces loud, never as OK, never omitted.
type PostBootInfo struct {
	Available bool `json:"available"`

	State  string `json:"state"`            // found / absent / unmeasurable
	Source string `json:"source,omitempty"` // persistent_journal / wtmp (when found)
	Reason string `json:"reason,omitempty"` // machine-stable code when not cleanly found
	// PriorBoots is how many boots before the current one journald can see (0 == only
	// the current boot is on record).
	PriorBoots int `json:"prior_boots,omitempty"`

	// --- findings, meaningful only when State == "found" ---
	// ShutdownChecked is false when the source can't speak to clean-vs-unclean (e.g. a
	// coarse wtmp-only read that found no crash marker but can't fully confirm). When
	// UncleanShutdown is true the prior boot ended without a recorded shutdown sequence
	// (power loss, hard reset, panic) — the core "what stopped it" signal.
	ShutdownChecked bool `json:"shutdown_checked"`
	UncleanShutdown bool `json:"unclean_shutdown,omitempty"`

	// OOM kills observed in the PRIOR boot (distinct from OOMCollector, which reads the
	// current boot's last 24h). Victims lists up to a few process names.
	// OOMChecked is false when the --grep sub-call itself failed for a reason other
	// than "no matches" (journalctl exits non-zero on zero matches too, so a genuine
	// read failure and a genuinely clean boot are otherwise indistinguishable) —
	// mirrors ShutdownChecked's "not measured" vs "measured and clean" distinction.
	OOMChecked bool     `json:"oom_checked"`
	OOMKills   int      `json:"oom_kills,omitempty"`
	OOMVictims []string `json:"oom_victims,omitempty"`

	// KernelPanic is true when the prior boot logged a panic / oops / fatal BUG; Hint
	// carries a one-line excerpt of the matching kernel line. PanicChecked mirrors
	// OOMChecked above.
	PanicChecked bool   `json:"panic_checked"`
	KernelPanic  bool   `json:"kernel_panic,omitempty"`
	PanicHint    string `json:"panic_hint,omitempty"`
}
