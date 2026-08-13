package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkPostBoot renders the prior-boot forensic verdict. It NEVER returns empty for a
// host that could be assessed: an unmeasurable prior boot is surfaced (not omitted), an
// absent one is stated plainly, and a clean one gets one recognition line — so an empty
// post-boot panel can never read as a silent "OK". Findings (unclean stop / OOM / panic)
// are WARN: they are post-mortem (the box is back up), not an active emergency.
func checkPostBoot(pb models.PostBootInfo) []models.Insight {
	if !pb.Available {
		return nil
	}
	switch pb.State {
	case "unmeasurable":
		return []models.Insight{postBootUnmeasurable(pb)}
	case "absent":
		return []models.Insight{insight("INFO", "PostBoot",
			"no prior boot on record — this is the first boot since the system began persisting boot logs (not a clean-shutdown confirmation, just no history)",
			nil)}
	case "found":
		return postBootFindings(pb)
	default:
		// internal-analysis-06-02: an unrecognized State must not silently drop
		// whatever findings the payload carries (KernelPanic/OOMKills/
		// UncleanShutdown are only consulted when State=="found"). Real captures
		// only ever set found/absent/unmeasurable — anything else means a
		// corrupted or tampered replay bundle, which must not read as "nothing
		// wrong ever happened".
		return []models.Insight{unverifiedInsight("INFO", "PostBoot",
			fmt.Sprintf("prior-boot state %q is not a recognized value (expected found/absent/unmeasurable) — post-boot forensics could not be confirmed", pb.State),
			nil)}
	}
}

// postBootUnmeasurable explains WHY the prior boot couldn't be read — always shown, never
// OK. INFO rather than WARN: volatile journald is the default on many cloud/minimal images
// and is not itself a fault (it only bites after an unexpected reboot), so a WARN on every
// such host would be false-alarm noise.
func postBootUnmeasurable(pb models.PostBootInfo) models.Insight {
	switch pb.Reason {
	case "no_persistent_journal":
		return insight("INFO", "PostBoot",
			"prior-boot forensics unavailable — journald is volatile, so the previous boot's logs did not survive the reboot",
			[]string{"to enable: set Storage=persistent in /etc/systemd/journald.conf (creates /var/log/journal), then restart systemd-journald"})
	case "journal_unreadable":
		return unverifiedInsight("INFO", "PostBoot",
			"prior-boot forensics unavailable — the journal is present but not readable as this user",
			[]string{"run as root (or join the systemd-journal group) to read the previous boot"})
	case "non_systemd_no_wtmp":
		return insight("INFO", "PostBoot",
			"prior-boot forensics unavailable — non-systemd host with no wtmp, so there is no cross-boot record to read",
			nil)
	}
	return unverifiedInsight("INFO", "PostBoot", "prior-boot forensics unavailable (could not read any cross-boot source)", nil)
}

func postBootFindings(pb models.PostBootInfo) []models.Insight {
	var out []models.Insight
	if pb.KernelPanic {
		hint := ""
		if pb.PanicHint != "" {
			hint = " — " + pb.PanicHint
		}
		out = append(out, insight("WARN", "PostBoot",
			"the previous boot logged a kernel panic / oops"+hint+" — the box most likely crashed rather than rebooting cleanly",
			[]string{"to inspect: journalctl -k --boot=-1"}))
	}
	if pb.OOMKills > 0 {
		victims := ""
		if len(pb.OOMVictims) > 0 {
			victims = " (victims: " + strings.Join(pb.OOMVictims, ", ") + ")"
		}
		out = append(out, insight("WARN", "PostBoot",
			fmt.Sprintf("the previous boot had %d OOM kill(s)%s — the host was under memory pressure before the reboot", pb.OOMKills, victims),
			[]string{"to inspect: journalctl -k --boot=-1 --grep 'Out of memory'"}))
	}
	if pb.ShutdownChecked && pb.UncleanShutdown {
		out = append(out, insight("WARN", "PostBoot",
			"the previous shutdown was unclean — no shutdown sequence was recorded, so the box stopped abruptly (power loss, hard reset, host eviction, or panic)",
			[]string{"to inspect: journalctl --boot=-1 (look for the tail — a clean stop ends in 'Reached target Shutdown')"}))
	}
	// internal-collectors-26-01: journalctl --grep exits non-zero on zero matches
	// too, so a genuine sub-call failure (ACL change mid-run, journal rotation, a
	// journalctl build without PCRE2/--grep support) is otherwise indistinguishable
	// from "checked, found nothing" — disclose it rather than silently reading
	// "found, 0 OOM kills, no kernel panic" for a boot dsd never actually inspected.
	// Journal-source only: the wtmp path never attempts these sub-checks at all
	// (a structurally different "not applicable", already disclosed via
	// postBootCleanLine's Source=="wtmp" branch below), not a failed sub-call.
	if pb.Source == "persistent_journal" {
		if !pb.OOMChecked {
			out = append(out, unverifiedInsight("INFO", "PostBoot",
				"prior-boot OOM-kill check could not be completed — the journalctl sub-call failed",
				[]string{"to inspect: journalctl -k --boot=-1 --grep 'Out of memory'"}))
		}
		if !pb.PanicChecked {
			out = append(out, unverifiedInsight("INFO", "PostBoot",
				"prior-boot kernel-panic check could not be completed — the journalctl sub-call failed",
				[]string{"to inspect: journalctl -k --boot=-1"}))
		}
	}
	if len(out) == 0 {
		out = append(out, insight("INFO", "PostBoot", postBootCleanLine(pb), nil))
	}
	return out
}

// postBootCleanLine is the recognition line when the prior boot was readable and nothing
// notable was found — asserting ONLY what was actually verified. The wtmp path is coarse:
// it can speak to clean-vs-unclean but CANNOT see OOM kills or kernel panics (those live
// only in the now-volatile journal), so it must not claim those were clean.
func postBootCleanLine(pb models.PostBootInfo) string {
	parts := []string{}
	if pb.ShutdownChecked && !pb.UncleanShutdown {
		parts = append(parts, "previous shutdown was clean")
	}
	if pb.Source == "wtmp" {
		parts = append(parts, "OOM/kernel-panic detail unavailable (no persistent journal to read the prior boot)")
		return "prior boot read via wtmp (coarse) — " + strings.Join(parts, "; ")
	}
	parts = append(parts, "no OOM kill or kernel panic in the prior boot")
	return "prior boot read via journal — " + strings.Join(parts, "; ")
}
