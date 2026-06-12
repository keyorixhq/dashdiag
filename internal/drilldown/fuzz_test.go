package drilldown

import (
	"strings"
	"testing"
)

// FuzzParseProcStatComm fuzzes the /proc/<pid>/stat comm splitter. The comm
// (process name) is attacker-influenced: an unprivileged local process or a
// container workload chooses its own name, including embedded parens/spaces
// that the kernel does not escape. Invariant: never panic, and when ok==true
// the reported name must be a substring of the input (no fabricated bytes).
func FuzzParseProcStatComm(f *testing.F) {
	seeds := []string{
		"1234 (nginx) S 1 1234 1234 0 -1 0",
		"5678 (Web Content) R 1 5678 5678",
		"99 (weird (nested) name) S 1 99 99",
		"0 () S",
		"(",
		")",
		")(",
		"",
		"no parens here",
		"1 (\x00nul) S",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, stat string) {
		name, _, ok := parseProcStatComm(stat)
		if ok && !strings.Contains(stat, name) {
			t.Fatalf("comm %q not a substring of input %q", name, stat)
		}
	})
}

// FuzzParseMountFromMessage and FuzzParseUnitFromMessage fuzz the regex
// extractors that pull a mount path / unit name out of a human-readable insight
// message. Messages can echo attacker-influenced strings (mount paths, unit
// names from logs). Invariant: never panic; output is always a substring of the
// input (the extractors must not fabricate path/unit content).
func FuzzParseMountFromMessage(f *testing.F) {
	seeds := []string{
		"filesystem on /mnt/data is full",
		"on /",
		"on /weird path (with parens)",
		"no mount here",
		"on ",
		"",
		"on /\x00",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, msg string) {
		got := parseMountFromMessage(msg)
		// "/" is the documented default when nothing matches; otherwise the
		// result must come from the input.
		if got != "/" && !strings.Contains(msg, strings.TrimRight(got, "(")) {
			t.Fatalf("mount %q not derived from input %q", got, msg)
		}
	})
}

func FuzzParseUnitFromMessage(f *testing.F) {
	seeds := []string{
		"unit foo.service has failed",
		"unit a.b.c has",
		"unit  has",
		"no unit token",
		"unit",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, msg string) {
		got := parseUnitFromMessage(msg)
		if got != "" && !strings.Contains(msg, got) {
			t.Fatalf("unit %q not derived from input %q", got, msg)
		}
	})
}
