//go:build linux

package collectors

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// SSDLC Layer 2 (ADR-0007 / THREAT_MODEL_CLI.md §5): fuzz the systemd tool-output
// parsers in the high-frequency Services collector. Their inputs are
// attacker-influenceable — a container or app can create units with adversarial
// names, and journal lines carry arbitrary message bodies — and they feed health
// verdicts (failed units, boot offenders). The false-OK risk is "garbled
// systemctl/journalctl output silently drops a failed unit or mis-parses state";
// the invariant exercised here is: never panic, and never emit a unit with an
// empty/typeless name.

func FuzzParseFailedUnits(f *testing.F) {
	seeds := []string{
		"postgresql.service loaded failed failed PostgreSQL Database\n",
		"a.service loaded failed failed\n",
		"x\x00y.service loaded failed failed nul-in-name\n",
		"not-a-unit summary line with no dot\n",
		"too few\n",
		"",
		"  \t  \n",
		strings.Repeat("x", 4096) + ".service loaded failed failed\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, out string) {
		for _, u := range parseFailedUnits(out) {
			// Contract: only real units (name carries a type suffix) are returned.
			if u.Name == "" || !strings.Contains(u.Name, ".") {
				t.Fatalf("parseFailedUnits returned a non-unit name %q for input %q", u.Name, out)
			}
		}
	})
}

func FuzzParseUnitShow(f *testing.F) {
	seeds := []string{
		"ExecMainStatus=0\nActiveState=failed\nSubState=failed\n",
		"ExecMainStatus=-1\nActiveState=active\n",
		"ExecMainStatus=notanumber\n",
		"NoEqualsSignHere\n",
		"=emptykey\nActiveState=\n",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, out string) {
		var u models.SystemdUnit
		parseUnitShow(out, &u) // invariant: never panic on arbitrary key=value output
	})
}

func FuzzParseBlame(f *testing.F) {
	seeds := []string{
		"4.210s postgresql.service\n2min 4.210s nginx.service\n450ms sshd.service\n",
		"1h 2min 3.000s heavy.service\n",
		"garbage\n",
		"5s only-duration-no-unit\n",
		"\t.service\n",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, out string) {
		_ = parseBlame(out, 5)
	})
}

func FuzzParseDurationMs(f *testing.F) {
	for _, s := range []string{"4.210s", "2min 4.210s", "450ms", "1h 2min 3.000s", "", "abc", "1e308s", "-5s", "NaNs"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = parseDurationMs(s)
	})
}

func FuzzParseJournalLines(f *testing.F) {
	seeds := []string{
		"May 19 10:00:00 host unit[123]: started cleanly\n",
		"no bracket colon format line\n",
		"]: leading-bracket-colon\n",
		"\x00]: nul prefix\n",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, out string) {
		_ = parseJournalLines(out)
	})
}
