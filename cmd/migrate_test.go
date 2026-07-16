package cmd

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/baseline"
)

// de builds a DiffEntry the way baseline.ComputeDiff formats them: "STATUS value".
func de(name, before, after string) baseline.DiffEntry {
	return baseline.DiffEntry{Name: name, Before: before, After: after}
}

func TestCertifyVerdict(t *testing.T) {
	cases := []struct {
		name    string
		diff    []baseline.DiffEntry
		want    string
		wantReg int
	}{
		{
			name: "clean migration — no regressions",
			diff: []baseline.DiffEntry{
				de("Network", "OK 3 up", "OK 3 up"),
				de("Disk", "OK 40%", "OK 40%"),
			},
			want: certPass, wantReg: 0,
		},
		{
			name: "VMware tools gate off after move is NOT a regression",
			// The whole point: a source-only check that vanishes on the destination
			// must not fail certification.
			diff: []baseline.DiffEntry{
				de("VMware", "OK tools running", "absent"),
			},
			want: certPass, wantReg: 0,
		},
		{
			name: "a source CRIT that vanished is an improvement, not a regression",
			diff: []baseline.DiffEntry{
				de("SomeCheck", "CRIT broken", "absent"),
			},
			want: certPass, wantReg: 0,
		},
		{
			name: "driver fell back — new WARN on destination",
			diff: []baseline.DiffEntry{
				de("Network", "OK vmxnet3", "WARN emulated e1000"),
			},
			want: certWarn, wantReg: 1,
		},
		{
			name: "disk grown-not-resized after move — OK to CRIT",
			diff: []baseline.DiffEntry{
				de("Disk", "OK 40%", "CRIT unresized"),
			},
			want: certFail, wantReg: 1,
		},
		{
			name: "brand-new problem check on destination (no source counterpart)",
			diff: []baseline.DiffEntry{
				de("CloudInit", "", "WARN did not run"),
			},
			want: certWarn, wantReg: 1,
		},
		{
			name: "improvement is not a regression",
			diff: []baseline.DiffEntry{
				de("Services", "WARN 1 failed", "OK 0 failed"),
			},
			want: certPass, wantReg: 0,
		},
		{
			name: "CRIT dominates WARN in a mixed diff",
			diff: []baseline.DiffEntry{
				de("Network", "OK vmxnet3", "WARN emulated"),
				de("Disk", "OK 40%", "CRIT unresized"),
				de("Services", "WARN 1 failed", "OK 0 failed"), // improvement, ignored
			},
			want: certFail, wantReg: 2,
		},
		// A confirmed source problem that becomes unverifiable (INFO — a collector
		// that couldn't measure it) on the destination must NOT read as a silent
		// PASS. Plain severity ordering alone would treat this as an improvement
		// (INFO ranks below CRIT/WARN, meaning "unknown" not "healthy") — the exact
		// false-PASS gap this test guards against.
		{
			name: "confirmed CRIT becomes unverifiable — must not silently PASS",
			diff: []baseline.DiffEntry{
				de("Disk", "CRIT unresized", "INFO could not measure"),
			},
			want: certWarn, wantReg: 1,
		},
		{
			name: "confirmed WARN becomes unverifiable — must not silently PASS",
			diff: []baseline.DiffEntry{
				de("Network", "WARN emulated", "INFO could not measure"),
			},
			want: certWarn, wantReg: 1,
		},
		// A previously-healthy check that becomes unverifiable is a real, if minor,
		// drop in confidence — flag it too, but it must never escalate past WARN on
		// its own (we don't know it's broken, just that we couldn't check).
		{
			name: "OK becomes unverifiable — WARN, not FAIL",
			diff: []baseline.DiffEntry{
				de("Sessions", "OK 2 users", "INFO could not measure"),
			},
			want: certWarn, wantReg: 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reg := certifyVerdict(c.diff)
			if got != c.want {
				t.Errorf("verdict = %q, want %q", got, c.want)
			}
			if len(reg) != c.wantReg {
				t.Errorf("regressions = %d, want %d", len(reg), c.wantReg)
			}
		})
	}
}

// TestManifestHostAndOS_Nil covers the nil-guard path in manifestHost/manifestOS.
func TestManifestHostAndOS_Nil(t *testing.T) {
	t.Parallel()
	if got := manifestHost(nil); got != "?" {
		t.Errorf("manifestHost(nil) = %q, want \"?\"", got)
	}
	if got := manifestOS(nil); got != "?" {
		t.Errorf("manifestOS(nil) = %q, want \"?\"", got)
	}
}

func TestStatusSeverityAbsentIsOK(t *testing.T) {
	if statusSeverity("absent") != sevOK {
		t.Error("absent must rank as OK — a vanished check is not a regression")
	}
	if statusSeverity("") != sevOK {
		t.Error("empty (never-present) must rank as OK")
	}
	if statusSeverity("crit") <= statusSeverity("warn") {
		t.Error("CRIT must outrank WARN (case-insensitive)")
	}
}

// TestStatusSeverityInfoIsUnknownNotOK guards against re-introducing the false-PASS
// gap: INFO (dsd's "couldn't measure this" vocabulary) must never rank the same as
// a confirmed-healthy OK, even though certifyVerdict no longer relies on a plain
// before<after comparison alone to catch it (see the unverifiable-regression cases
// in TestCertifyVerdict).
func TestStatusSeverityInfoIsUnknownNotOK(t *testing.T) {
	if statusSeverity("INFO") != sevUnknown {
		t.Error("INFO must rank as unknown, not OK — it means unverified, not healthy")
	}
	if statusSeverity("INFO") == sevOK {
		t.Error("INFO must not be indistinguishable from OK")
	}
}
