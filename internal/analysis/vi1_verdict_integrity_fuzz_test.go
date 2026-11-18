package analysis

// VI1 — generalised verdict integrity.
//
// DV1 hand-wrote monotonicity + false-OK oracles for three analysis verdict
// functions (CloudInit, DiskUsage, Drive). This file generalises that into ONE
// table-driven generator so adding a check is a single registry entry
// (verdictChecks below). Every registered check is driven through four oracles,
// each asserting a property that holds for ANY correct verdict function — there
// is no second implementation and no hand-specified expected output, so there is
// no false-positive direction as long as the per-check knobs/gaps encode true
// facts about that check:
//
//   (a) MONOTONICITY (metamorphic): worsening a single monotone metric must
//       never IMPROVE the verdict (its severity rank must not drop). The reverse
//       — improving never worsens — is the same inequality read the other way,
//       so one worsen direction per knob suffices. Only metrics that are
//       genuinely monotone for that check are registered as knobs (that is why
//       this is a curated table, not an automatic field walk): a value that is
//       bad both too-high and too-low, or a categorical field, is NOT a knob.
//
//   (b) FALSE-OK: a measurement-gap input (a *Unreadable/*Unverified sentinel
//       set, an unreachable mount, an unenumerable drive list) must yield an
//       Unverified/unknown insight, never a silent confident OK (an empty
//       result). This is the false-clean bug class (#575/#576/#921; the DNF/
//       zypper/apt fixes) — see internal/models/falseok_signal_registry_test.go
//       for the authoritative sentinel-field surface. Asserted in
//       TestVI1FalseOKGaps (deterministic, runs without -fuzz).
//
//   (c) IDEMPOTENCE & ORDER INDEPENDENCE: running a check twice on the same
//       input yields DeepEqual insights (pure function), and — for checks whose
//       input carries an aggregated slice (filesystems, drives) — permuting that
//       slice yields the same MULTISET of insights (aggregation is order-free).
//
//   (d) RESOURCE BOUND: every check run is wrapped in the shared DL1 resource
//       oracle (internal/testutil/resource). Meters enabled: Go-heap TotalAlloc
//       and wall time — the only two that can matter here, because these checks
//       are pure in-memory functions over already-collected structs (no fd, no
//       socket, no subprocess, no sleep), so the goroutine/fd/network meters
//       would be dead weight. The factor is calibrated generous (the 1 MiB floor
//       dominates for these tiny inputs); it exists to catch a super-linear
//       blow-up a pathological fuzzed struct could force, not to micro-benchmark.
//
// Realistic-input seam (task item d — the DD2 capture→replay seam). The verdict
// functions here consume already-decoded models.* structs; the realistic
// end-to-end path (replay bundle → collectors → model → verdict) is fuzzed by
// cmd.FuzzWholeBundleReplayVerdictFlip / cmd.FuzzWholeBundleReplay, which this
// generator complements by fuzzing the pure check seam directly at a far higher
// exec rate. Wiring a replay bundle straight into this generator's inputs is a
// ranked LEFTOVER in the VI1 report.
//
// Verified non-duplication: `grep "func Fuzz" internal/analysis` finds no
// pre-existing analysis-level verdict fuzzer; the existing metamorphic verdict
// targets live at the collector counter seam (packages_metamorphic_fuzz) and the
// whole-bundle replay seam (cmd), neither of which exercises these check
// functions' monotonicity/false-OK directly.

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// resourceFactor is the per-input allocation amplification ceiling for a single
// check run (bytes allocated <= factor*inputLen + 1 MiB). Generous on purpose —
// see the package comment (d).
const resourceFactor = 4096

// --- severity rank ---------------------------------------------------------

// levelRank maps an insight Level to the user-facing verdict severity. Empty /
// absent == OK == 0. The Unverified flag is a SEPARATE axis (handled by the
// false-OK oracle); for the monotonicity oracle we rank the Level the operator
// actually sees.
func levelRank(l string) int {
	switch l {
	case "CRIT":
		return 3
	case "WARN":
		return 2
	case "INFO":
		return 1
	default: // "OK", "" and any unknown label — treated as OK
		return 0
	}
}

// verdictRank is the worst (max) Level rank across a check's insights. An empty
// slice is a confident OK (rank 0).
func verdictRank(ins []models.Insight) int {
	r := 0
	for _, i := range ins {
		if x := levelRank(i.Level); x > r {
			r = x
		}
	}
	return r
}

func vi1HasUnverified(ins []models.Insight) bool {
	for _, i := range ins {
		if i.Unverified {
			return true
		}
	}
	return false
}

// insightMultiset renders insights into a sorted, order-independent fingerprint
// of the VERDICT — (Level, Check) per insight — for the order-independence
// oracle. It deliberately does NOT include Message: a correct aggregated insight
// may legitimately embed a list of host-derived names (drives, mounts) joined in
// input order, so the message text is not order-invariant even though the
// verdict is. Keying on (Level, Check) asserts the sound property — the same set
// of findings at the same severities, regardless of input order — while a
// reordering that drops/adds a finding or changes a severity still shows up as a
// multiset difference (count- and level-sensitive). See the VI1 report's "Drive
// name-list ordering" finding for the message-text order-dependence this scoping
// consciously excludes rather than asserts.
func insightMultiset(ins []models.Insight) []string {
	out := make([]string, 0, len(ins))
	for _, i := range ins {
		out = append(out, i.Level+"\x00"+i.Check)
	}
	sort.Strings(out)
	return out
}

// --- deterministic fuzz-byte consumer --------------------------------------

// drip pulls deterministic scalars out of the fuzz byte stream. Out of bytes ->
// zero values (a check must behave on an all-zero input just as well).
type drip struct {
	b []byte
	i int
}

func (d *drip) u8() byte {
	if d.i >= len(d.b) {
		return 0
	}
	v := d.b[d.i]
	d.i++
	return v
}

// pct returns a value in [0, 120] so the >100 edge is exercised.
func (d *drip) pct() float64 { return float64(d.u8()) / 255.0 * 120.0 }

// upto returns an int in [0, n).
func (d *drip) upto(n int) int {
	if n <= 0 {
		return 0
	}
	return int(d.u8()) % n
}

func (d *drip) boolean() bool { return d.u8()&1 == 1 }

// --- the registry ----------------------------------------------------------

type worsener struct {
	name string
	// fn returns a COPY of in with one monotone metric moved toward "worse".
	// It must not mutate in (copy any slice it touches).
	fn func(in any) any
}

type gapCase struct {
	name  string
	input any
}

type vcheck struct {
	name  string
	build func(d *drip) any
	run   func(in any) []models.Insight
	// worsen lists monotone metrics; each must only ever raise (never lower) the
	// verdict rank for this check.
	worsen []worsener
	// gaps are measurement-gap inputs that MUST produce an Unverified insight.
	gaps []gapCase
	// permute (optional) returns a copy with an aggregated slice reordered; the
	// resulting insight multiset must be unchanged.
	permute func(in any) any
}

// The checks that take Thresholds use the package-level defaultThresh
// (DefaultThresholds(EnvBareMetal), declared in heuristics_test.go); a fixed
// baseline keeps the registered knobs monotone.

// vi1NoCtr is "not in a container" — the common case; keeps container-
// suppression branches out of the way so the registered knobs stay monotone.
var vi1NoCtr = platform.ContainerContext{}

var verdictChecks = []vcheck{
	{
		name:  "CloudInit",
		build: buildCloudInit,
		run:   func(in any) []models.Insight { return checkCloudInit(in.(models.CloudInitInfo)) },
		worsen: []worsener{{
			name: "add fatal cloud-init error",
			fn: func(in any) any {
				c := in.(models.CloudInitInfo)
				c.Errors = append(append([]string{}, c.Errors...), "vi1-planted fatal error")
				return c
			},
		}},
		gaps: []gapCase{
			{"status unreadable", models.CloudInitInfo{Available: true, StatusUnverified: true}},
		},
	},
	{
		name:  "Memory",
		build: buildMemory,
		run:   func(in any) []models.Insight { return checkMemory(in.(models.MemoryInfo), defaultThresh, vi1NoCtr) },
		worsen: []worsener{{
			name: "raise RAM used%",
			fn: func(in any) any {
				m := in.(models.MemoryInfo)
				m.UsedPct = clampPct(m.UsedPct + 40)
				return m
			},
		}},
		gaps: []gapCase{
			{"meminfo unreadable", models.MemoryInfo{MeminfoUnreadable: true}},
			{"ECC counters unreadable", models.MemoryInfo{EDACAvailable: true, EDACCountersUnreadable: true}},
		},
	},
	{
		name:  "Swap",
		build: buildSwap,
		run:   func(in any) []models.Insight { return checkSwap(in.(models.SwapInfo), defaultThresh) },
		worsen: []worsener{{
			name: "raise swap used%",
			fn: func(in any) any {
				s := in.(models.SwapInfo)
				s.UsedPct = clampPct(s.UsedPct + 40)
				return s
			},
		}},
		gaps: []gapCase{
			{"/proc/swaps unreadable", models.SwapInfo{SwapsUnreadable: true}},
			{"zram unreadable", models.SwapInfo{ZramUnreadable: true}},
		},
	},
	{
		name:  "DiskUsage",
		build: buildDisk,
		run:   func(in any) []models.Insight { return checkDisk(in.(models.DiskInfo), defaultThresh) },
		worsen: []worsener{{
			name: "raise every filesystem used%",
			fn: func(in any) any {
				d := in.(models.DiskInfo)
				fs := append([]models.FilesystemInfo(nil), d.Filesystems...)
				for i := range fs {
					fs[i].UsedPct = clampPct(fs[i].UsedPct + 40)
				}
				d.Filesystems = fs
				return d
			},
		}},
		gaps: []gapCase{
			{"unreachable mount", models.DiskInfo{UnreachableMounts: []models.UnreachableMount{{Mount: "/data", FSType: "nfs", Error: "stale"}}}},
			{"drive list unreadable", models.DiskInfo{DrivesListUnreadable: true}},
			{"zfs list read failed", models.DiskInfo{ZFSListReadFailed: true}},
		},
		permute: func(in any) any {
			d := in.(models.DiskInfo)
			fs := append([]models.FilesystemInfo(nil), d.Filesystems...)
			for i, j := 0, len(fs)-1; i < j; i, j = i+1, j-1 {
				fs[i], fs[j] = fs[j], fs[i]
			}
			d.Filesystems = fs
			return d
		},
	},
	{
		name:  "Drive",
		build: buildNVMe,
		run:   func(in any) []models.Insight { return checkNVMe(in.(models.NVMeInfo)) },
		// No monotone knob registered: NVMe scoring gates each device through a
		// physical-plausibility filter (nvmeSmartPlausible), so bumping a raw
		// SMART counter can flip a device from "scored" to "skipped" and LOWER the
		// rank — not a real inversion, a plausibility artifact. Left as a LEFTOVER
		// (needs a plausibility-preserving worsen). False-OK + order-independence
		// still apply.
		gaps: []gapCase{
			{"drive enumeration unreadable", models.NVMeInfo{DrivesListUnreadable: true}},
			{"dangerous SMART fields unread", models.NVMeInfo{Devices: []models.NVMeDevice{{
				Name: "nvme0", SmartRead: true, SmartDangerousFieldsUnread: true,
			}}}},
		},
		permute: func(in any) any {
			n := in.(models.NVMeInfo)
			dv := append([]models.NVMeDevice(nil), n.Devices...)
			for i, j := 0, len(dv)-1; i < j; i, j = i+1, j-1 {
				dv[i], dv[j] = dv[j], dv[i]
			}
			n.Devices = dv
			return n
		},
	},
}

func clampPct(v float64) float64 {
	if v > 120 {
		return 120
	}
	if v < 0 {
		return 0
	}
	return v
}

// --- builders (fuzz bytes -> model struct) ---------------------------------

func buildCloudInit(d *drip) any {
	statuses := []string{"done", "running", "error", "disabled", "not run", ""}
	c := models.CloudInitInfo{
		Available:        d.boolean() || true, // mostly available so checks actually run
		Status:           statuses[d.upto(len(statuses))],
		Datasource:       []string{"ec2", "gce", "nocloud", ""}[d.upto(4)],
		StatusUnverified: d.u8() < 8, // rarely a gap, mostly a real reading
	}
	if d.boolean() {
		c.ExtendedStatus = "degraded done"
	}
	for n := d.upto(3); n > 0; n-- {
		c.Errors = append(c.Errors, "err")
	}
	for n := d.upto(3); n > 0; n-- {
		c.RecoverableErrors = append(c.RecoverableErrors, "rec")
	}
	return c
}

func buildMemory(d *drip) any {
	return models.MemoryInfo{
		TotalGB:                float64(1 + d.upto(256)),
		FreeGB:                 float64(d.upto(16)),
		UsedPct:                d.pct(),
		SlabMB:                 float64(d.upto(4096)),
		OverCommitted:          d.boolean(),
		OvercommitMode:         d.upto(3),
		EDACAvailable:          d.boolean(),
		CorrectedErrors:        int64(d.upto(50)),
		UncorrectedErrors:      int64(d.upto(5)),
		EDACCountersUnreadable: d.u8() < 8,
		MeminfoUnreadable:      d.u8() < 8,
	}
}

func buildSwap(d *drip) any {
	return models.SwapInfo{
		TotalGB:          float64(d.upto(64)),
		UsedGB:           float64(d.upto(64)),
		UsedPct:          d.pct(),
		PagesInPerSec:    float64(d.upto(5000)),
		PagesOutPerSec:   float64(d.upto(5000)),
		ZramDevices:      d.upto(2),
		MemPressureLevel: d.upto(3),
		SwapsUnreadable:  d.u8() < 8,
		ZramUnreadable:   d.u8() < 8,
	}
}

func buildDisk(d *drip) any {
	fstypes := []string{"ext4", "xfs", "btrfs", "squashfs", "iso9660"}
	var di models.DiskInfo
	for n := d.upto(6); n >= 0; n-- {
		fs := models.FilesystemInfo{
			Mount:         []string{"/", "/var", "/home", "/boot", "/data"}[d.upto(5)],
			Device:        "/dev/sda" + fmt.Sprint(n),
			FSType:        fstypes[d.upto(len(fstypes))],
			TotalGB:       float64(1 + d.upto(1000)),
			UsedPct:       d.pct(),
			InodesUsedPct: d.pct(),
			ReadOnly:      d.boolean(),
			DeviceSizeGB:  float64(d.upto(1000)),
		}
		di.Filesystems = append(di.Filesystems, fs)
	}
	di.DrivesListUnreadable = d.u8() < 6
	di.ZFSListReadFailed = d.u8() < 6
	return di
}

func buildNVMe(d *drip) any {
	var n models.NVMeInfo
	for k := d.upto(5); k >= 0; k-- {
		dev := models.NVMeDevice{
			Name:                       "nvme" + fmt.Sprint(k),
			CriticalWarning:            d.upto(4),
			MediaErrors:                int64(d.upto(10)),
			SmartRead:                  d.boolean(),
			SmartDangerousFieldsUnread: d.u8() < 16,
		}
		if !dev.SmartRead {
			dev.SmartUnreadReason = []string{"needs_root", "error", "tool_absent", ""}[d.upto(4)]
		}
		n.Devices = append(n.Devices, dev)
	}
	n.DrivesListUnreadable = d.u8() < 6
	return n
}

// --- the generator ---------------------------------------------------------

// runOracles drives one fuzz input (or seed) through the monotonicity,
// idempotence, order-independence and resource oracles for every registered
// check. The false-OK oracle is separate (TestVI1FalseOKGaps) because its inputs
// are fixed gap cases, not fuzzed.
func runOracles(t *testing.T, data []byte) {
	t.Helper()
	d := &drip{b: data}
	inLen := len(data) + 1
	for _, c := range verdictChecks {
		in := c.build(d)

		// (d) resource-bounded base run.
		var base []models.Insight
		resource.Check(t, inLen, resourceFactor, func() { base = c.run(in) })

		// (c) idempotence.
		if again := c.run(in); !reflect.DeepEqual(base, again) {
			t.Fatalf("NOT IDEMPOTENT: check %s produced different insights on a second identical run:\n a=%+v\n b=%+v", c.name, base, again)
		}
		baseRank := verdictRank(base)

		// (a) monotonicity: worsening a metric must never improve the verdict.
		for _, w := range c.worsen {
			worseRank := verdictRank(c.run(w.fn(in)))
			if worseRank < baseRank {
				t.Fatalf("MONOTONICITY VIOLATION: check %s, knob %q: worsening the metric IMPROVED the verdict (rank %d -> %d). base input=%+v",
					c.name, w.name, baseRank, worseRank, in)
			}
		}

		// (c) order independence of aggregation.
		if c.permute != nil {
			got := insightMultiset(c.run(c.permute(in)))
			want := insightMultiset(base)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("ORDER DEPENDENCE: check %s produced a different insight multiset after permuting its aggregated slice:\n want=%v\n got =%v", c.name, want, got)
			}
		}
	}
}

func FuzzVerdictIntegrity(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{255, 255, 255, 255, 255, 255, 255, 255})
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	f.Add([]byte{200, 10, 250, 3, 90, 0, 120, 7, 180, 2, 60, 9})
	f.Fuzz(func(t *testing.T, data []byte) {
		runOracles(t, data)
	})
}

// TestVI1VerdictIntegritySeeds exercises every oracle on a fixed corpus so the
// generator runs on every `go test ./internal/analysis` even without -fuzz.
func TestVI1VerdictIntegritySeeds(t *testing.T) {
	seeds := [][]byte{
		{}, {0, 0, 0, 0},
		{255, 255, 255, 255, 255, 255, 255, 255},
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		{200, 10, 250, 3, 90, 0, 120, 7, 180, 2, 60, 9},
		{100, 100, 100, 100, 100, 100, 100, 100, 100, 100},
	}
	for i, s := range seeds {
		t.Run(fmt.Sprintf("seed%d", i), func(t *testing.T) { runOracles(t, s) })
	}
}

// TestVI1FalseOKGaps is the false-OK oracle: for every registered gap case, the
// check must surface an Unverified insight — never a silent confident OK (empty
// result). This is the false-clean bug class the DNF/zypper/apt fixes closed.
func TestVI1FalseOKGaps(t *testing.T) {
	for _, c := range verdictChecks {
		for _, g := range c.gaps {
			t.Run(c.name+"/"+g.name, func(t *testing.T) {
				out := c.run(g.input)
				if len(out) == 0 {
					t.Fatalf("FALSE-OK: check %s returned a silent OK (no insights) for measurement-gap input %q — must disclose it as Unverified", c.name, g.name)
				}
				if !vi1HasUnverified(out) {
					t.Fatalf("FALSE-OK: check %s returned insights but NONE marked Unverified for gap input %q — a confident verdict on unmeasured data:\n %+v", c.name, g.name, out)
				}
			})
		}
	}
}
