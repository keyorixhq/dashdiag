//go:build linux

package cmd

// FuzzWholeBundleReplayVerdictFlip is oracle 3 for the whole-bundle replay fuzzer
// (FuzzWholeBundleReplay, #1099, shipped oracles 1 no-panic + 2 bounded-work): a
// METAMORPHIC "no verdict flip" check. Where oracles 1+2 assert broad, cheap
// properties that hold for ANY input, oracle 3 asserts a correctness invariant with
// NO second implementation and NO hand-specified expected output — the exact same
// idiom as internal/collectors/packages_metamorphic_fuzz_linux_test.go's
// FuzzAptAccumulateUpdateMetamorphic, scaled up to the whole pipeline (every
// collector, the real analysis thresholds, and the real exit-code mapping, not one
// parser function).
//
// The property: a FIXED benign baseline bundle covers six high-value seams (dnf
// advisory, thermal, EDAC, meminfo, /proc/loadavg, smartctl). For each seam, a
// mutation that is PROVABLY verdict-neutral BY CONSTRUCTION — i.e. this file's own
// doc comments below cite the exact parsing code line proving the mutated bytes are
// ignored, permuted-but-summed, or otherwise cannot change what the seam reports —
// must never change the overall verdict class `dsd replay` would report
// (cmd/replay.go's runReplay → internal/render/health.go's PrintSummary →
// exitCodeFromInsights: 0=OK, 1=WARN, 2=CRIT). A flip is a silent miscount or a
// dropped/duplicated record, not a crash — the dashdiag analogue of a keyorix
// security invariant.
//
// Two seams from the original task list are DELIBERATELY DROPPED, not stubbed:
//   - "lsblk-json": `lsblk` does not appear anywhere in this codebase's collectors —
//     the only repo hit is a human-facing hint string in
//     internal/analysis/heuristics_fstab.go, never exec.Run. No seam exists to fuzz.
//   - "ip-json": every real `ip` invocation in this codebase is plain text (`ip route
//     get`, `ip route show default`, `ip neigh show`, `ip link show`), never `ip
//     -json`/`ip -j`. The only `-j`-flag JSON usage anywhere is `tdnf -j
//     updateinfo`/`tdnf -j repolist` (Photon OS package manager) — unrelated to
//     networking. Per this task's own instruction ("if the backlog idea doesn't
//     match how the code works, STOP and report"), this seam is dropped rather than
//     harnessing a path production never takes.
//
// Positive control (run once, outside f.Fuzz, per this task's design): the baseline
// bundle must (a) yield a non-trivial verdict class (WARN — driven by the
// baseline's two Important dnf advisories AND its non-zero SMART MediaErrors, so
// either alone would already satisfy this; deliberately NOT Critical/CRIT, which
// is exitCodeFromInsights's ceiling and would leave no headroom to observe a
// verdict-escalating bug as a flip — see the dnf baseline consts' own doc comment)
// and (b) every one of the six seams must have actually produced data in the
// collected results — so "no data" can never pass this oracle vacuously. Both are
// asserted with f.Fatalf before f.Fuzz runs.
//
// Sound: every assertion is an EQUALITY that must hold for any correct
// implementation of the six parsers involved — never "must be healthy," never "must
// succeed" on arbitrary input.
import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── seam content ────────────────────────────────────────────────────────────────

// seamContent is every mutable byte range across the six seams. Each field starts
// at its seamDefaults() baseline; a mutation overrides exactly ONE field (or one
// closely-related pair, e.g. the two thermal zones) and leaves the rest untouched,
// so a verdict flip can always be attributed to a single seam+mutation.
type seamContent struct {
	dnfLine1, dnfLine2             string // dnf advisory list output (two distinct records)
	thermalZone0, thermalZone1     string // /sys/class/thermal/thermal_zone{0,1}/temp
	edacMC0CE, edacMC0UE           string // /sys/devices/system/edac/mc/mc0/{ce,ue}_count
	edacMC1CE, edacMC1UE           string // mc1's own counters
	edacDirs                       []string
	meminfoLines                   []string // /proc/meminfo lines
	loadavg                        string   // /proc/loadavg
	smartHealth                    string   // smartctl -H /dev/sda
	smartAttrLine1, smartAttrLine2 string   // smartctl -A /dev/sda (SATA failure-attr lines)
}

// Two well-formed, DISTINCT DNF4-format advisory lines: "ADVISORY-ID severity/Sec.
// package" — packages_linux.go's collectDNF (line ~356-367) classifies by whether
// fields[1] contains "/" or "Sec" (it does, on both), so both are unambiguously
// DNF4 regardless of any mutation applied to either line individually. Both are
// Important (WARN), not Critical (CRIT) — CRIT is exitCodeFromInsights's ceiling
// (2), so a Critical baseline would saturate the verdict and make it structurally
// impossible for any OTHER seam's bug to ever be observed as a flip. Leaving
// headroom to CRIT here is what makes a bug that falsely escalates severity (this
// file's own red-proof: a comment line miscounted as a Critical advisory)
// detectable at all.
const (
	dnfBaselineLine1 = "RHSA-2024:0001 Important/Sec. openssl-1.1.1w.x86_64"
	dnfBaselineLine2 = "RHSA-2024:0002 Important/Sec. curl-7.0.x86_64"
)

// Two SATA SMART failure-attribute lines in smartctl -A's real tabular shape: "ID
// NAME FLAG VALUE WORST THRESH TYPE UPDATED WHEN_FAILED RAW_VALUE" (10
// whitespace-fields, RAW_VALUE last) — disk_linux.go's parseSMARTAttributes
// (isSATAFailureAttr branch, line ~262-268) accumulates the last field into
// s.MediaErrors for any line whose lowercased text contains
// "reallocated_sector_ct"/"current_pending_sector"/"offline_uncorrectable", making
// MediaErrors a pure per-line sum with no cross-line state.
const (
	smartBaselineAttr1 = "  5 Reallocated_Sector_Ct  0x0033  100 100 010  Pre-fail  Always  -  1"
	smartBaselineAttr2 = "197 Current_Pending_Sector 0x0032  100 100 000  Old_age   Always  -  1"
)

func seamDefaults() seamContent {
	return seamContent{
		dnfLine1:     dnfBaselineLine1,
		dnfLine2:     dnfBaselineLine2,
		thermalZone0: "45000", // 45.0C - present, well under the 85C WARN threshold
		thermalZone1: "40000",
		edacMC0CE:    "1",
		edacMC0UE:    "0",
		edacMC1CE:    "1",
		edacMC1UE:    "0",
		edacDirs:     []string{"mc0", "mc1"},
		meminfoLines: []string{
			"MemTotal:       16384000 kB",
			"MemFree:         8192000 kB",
			"MemAvailable:   10240000 kB",
		},
		loadavg:        "0.10 0.20 0.30 1/234 5678",
		smartHealth:    "SMART overall-health self-assessment test result: PASSED",
		smartAttrLine1: smartBaselineAttr1,
		smartAttrLine2: smartBaselineAttr2,
	}
}

// buildBundleFrom assembles a full replay bundle from c, wiring every one of the
// six seams' full production prerequisite chain — not just the "interesting" byte
// range — so each seam is reached exactly the way `dsd replay` reaches it.
func buildBundleFrom(c seamContent) *source.Bundle {
	dnfAdvisory := c.dnfLine1 + "\n" + c.dnfLine2 + "\n"
	meminfo := strings.Join(c.meminfoLines, "\n") + "\n"
	loadavg := c.loadavg + "\n"

	b := buildWholeBundle(dnfAdvisory, meminfo, loadavg)

	// buildWholeBundle seeds the DNF repo gate + advisory scan, but not the
	// package-manager DETECTION probe itself (detectPackageManager,
	// packages_linux.go:129-145, tries zypper/dnf/apt/tdnf --version in order,
	// picking the first that exits 0) — the original oracle-1+2 harness never
	// needed real DNF data, only a non-empty result set. This harness's own
	// positive control needs collectDNF to actually run, so "dnf --version" must
	// succeed too (zypper is left unseeded so it fails through as usual).
	b.PutCmd("dnf", []string{"--version"}, "dnf version 4.14.0\n", 0)

	// ClockCollector (clock.go:80-86) is OUTSIDE the six controlled seams, but on a
	// recording gap it falls back to a LIVE adjtimex(2) read of the machine actually
	// running this test — not a fixed zero value — so its Clock CRIT/WARN/OK verdict
	// would otherwise depend on whether THAT machine's kernel clock happens to be
	// NTP-synced, making the overall baseline verdict non-deterministic across
	// hosts/CI runners. Seed it explicitly synced so Clock never contributes to (or
	// masks a flip in) the six seams under test.
	b.PutCached("clock/state", []byte(`{"synced":true,"offset_ms":0,"source":"ntp"}`))

	// Thermal: fallback path (readThermalZone, thermal_linux.go) — leave
	// /sys/class/hwmon/hwmon* unseeded (ErrNotRecorded on Glob, discarded by the
	// production code, `_`) so the collector falls through to this glob.
	b.PutGlob("/sys/class/thermal/thermal_zone*/temp", []string{
		"/sys/class/thermal/thermal_zone0/temp",
		"/sys/class/thermal/thermal_zone1/temp",
	})
	b.PutFile("/sys/class/thermal/thermal_zone0/temp", []byte(c.thermalZone0+"\n"))
	b.PutFile("/sys/class/thermal/thermal_zone1/temp", []byte(c.thermalZone1+"\n"))

	// EDAC (read by MemoryCollector, memory.go:120): mc*/ce_count needs a Stat hit
	// too (fileExists gate, edac_linux.go:43) on top of the ReadFile.
	b.PutDir("/sys/devices/system/edac/mc", c.edacDirs)
	b.PutStat("/sys/devices/system/edac/mc/mc0/ce_count", source.FileMeta{})
	b.PutFile("/sys/devices/system/edac/mc/mc0/ce_count", []byte(c.edacMC0CE+"\n"))
	b.PutFile("/sys/devices/system/edac/mc/mc0/ue_count", []byte(c.edacMC0UE+"\n"))
	b.PutStat("/sys/devices/system/edac/mc/mc1/ce_count", source.FileMeta{})
	b.PutFile("/sys/devices/system/edac/mc/mc1/ce_count", []byte(c.edacMC1CE+"\n"))
	b.PutFile("/sys/devices/system/edac/mc/mc1/ue_count", []byte(c.edacMC1UE+"\n"))

	// smartctl: the full prerequisite chain collectLinuxExtras walks before it ever
	// calls collectSMART — /proc/mounts (DiskCollector.Collect, disk.go:123: openFile
	// on it is the FIRST thing the collector does; an unrecorded/failed open returns
	// the whole collector's error BEFORE collectLinuxExtras/SMART ever run — an empty
	// file is a valid, zero-entry mount table), /proc/partitions (one real,
	// non-virtual "sda" entry), the sysfs type/size/model reads, and the lookPath
	// gate.
	b.PutFile("/proc/mounts", []byte(""))
	b.PutFile("/proc/partitions", []byte(
		"major minor  #blocks  name\n\n   8        0  100000000 sda\n"))
	b.PutFile("/sys/block/sda/queue/rotational", []byte("0\n"))
	b.PutFile("/sys/block/sda/size", []byte("999999999\n"))
	b.PutFile("/sys/block/sda/device/model", []byte("Samsung SSD 980\n"))
	b.PutCached("lookpath/smartctl", []byte("/usr/sbin/smartctl"))
	b.PutCmd("smartctl", []string{"-H", "/dev/sda"}, c.smartHealth+"\n", 0)
	b.PutCmd("smartctl", []string{"-A", "/dev/sda"},
		c.smartAttrLine1+"\n"+c.smartAttrLine2+"\n", 0)

	return b
}

// ── verdict + positive-control plumbing ──────────────────────────────────────────

// verdictClass mirrors runReplay's own verdict computation (replay.go:183,
// `renderer.PrintSummary(insights, 0)`) exactly, via the one call shape that has NO
// side effect: in ModeJSON, PrintSummary (internal/render/health.go:1554) returns
// exitCodeFromInsights(insights) immediately, without printing anything — 0=OK,
// 1=WARN, 2=CRIT.
func verdictClass(insights []models.Insight) int {
	return render.NewRenderer(output.ModeJSON).PrintSummary(insights, 0)
}

func findResult(results []runner.Result, name string) *runner.Result {
	for i := range results {
		if results[i].Name == name {
			return &results[i]
		}
	}
	return nil
}

func dnfProducedData(results []runner.Result) bool {
	r := findResult(results, "Packages")
	if r == nil {
		return false
	}
	info, ok := r.Data.(*models.PackagesInfo)
	return ok && info != nil && info.SecurityUpdates > 0
}

func thermalProducedData(results []runner.Result) bool {
	r := findResult(results, "CPU Thermal")
	if r == nil {
		return false
	}
	info, ok := r.Data.(*models.ThermalInfo)
	return ok && info != nil && info.CPUTempC > 0
}

func edacProducedData(results []runner.Result) bool {
	r := findResult(results, "Memory")
	if r == nil {
		return false
	}
	info, ok := r.Data.(*models.MemoryInfo)
	return ok && info != nil && info.EDACAvailable && info.CorrectedErrors > 0
}

func meminfoProducedData(results []runner.Result) bool {
	r := findResult(results, "Memory")
	if r == nil {
		return false
	}
	info, ok := r.Data.(*models.MemoryInfo)
	return ok && info != nil && info.TotalGB > 0
}

func loadavgProducedData(results []runner.Result) bool {
	r := findResult(results, "CPU Load")
	if r == nil {
		return false
	}
	info, ok := r.Data.(*models.CPUInfo)
	return ok && info != nil && info.LoadAvg1 > 0
}

func smartProducedData(results []runner.Result) bool {
	r := findResult(results, "Disk")
	if r == nil {
		return false
	}
	info, ok := r.Data.(*models.DiskInfo)
	if !ok || info == nil {
		return false
	}
	for _, d := range info.Drives {
		if d.SMART != nil && d.SMART.MediaErrors > 0 {
			return true
		}
	}
	return false
}

// ── mutation helpers ──────────────────────────────────────────────────────────────

// oneLine collapses extra to a single line, so an "append as a new line" mutation
// can never smuggle in an ADDITIONAL, unprefixed line the fuzzer fully controls
// (which could otherwise accidentally reproduce a real key/format the parser DOES
// act on — e.g. a bare "MemTotal: 1" line).
func oneLine(extra string) string {
	extra = strings.ReplaceAll(extra, "\n", " ")
	return strings.ReplaceAll(extra, "\r", " ")
}

// noColon removes every ':' from s, guaranteeing a colon-gated "must be ignored"
// parse branch (meminfo's len(parts)!=2 guard, SMART -A's colonIdx<0 guard) fires
// regardless of s's other content.
func noColon(s string) string { return strings.ReplaceAll(s, ":", "") }

// onlyWhitespace keeps only space/tab/CR/LF from s. Used to build noise that is
// PROVABLY safe to place around (never inside) a bare numeric value a parser feeds
// through strings.TrimSpace before parsing — TrimSpace strips any run of these
// exact runes from either end, regardless of how much or which ones.
func onlyWhitespace(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func reversed2(a, b string) (string, string) { return b, a }

// ── mutations ─────────────────────────────────────────────────────────────────────

type mutation struct {
	seam       string
	kind       string
	build      func(extra string) seamContent
	producedOK func(results []runner.Result) bool
}

func allMutations() []mutation {
	d := seamDefaults()

	return []mutation{
		{
			seam: "dnf", kind: "reorder-lines",
			// PERMUTATION invariance: collectDNF's severity counters
			// (SecurityUpdates/CriticalUpdates/ImportantUpdates, packages_linux.go
			// ~369-388) are incremented per-line with no cross-line state — the exact
			// idiom FuzzAptAccumulateUpdateMetamorphic already proved for apt.
			build: func(extra string) seamContent {
				c := d
				if len(extra)%2 == 0 {
					c.dnfLine1, c.dnfLine2 = reversed2(c.dnfLine1, c.dnfLine2)
				}
				return c
			},
			producedOK: dnfProducedData,
		},
		{
			seam: "dnf", kind: "append-skipped-prefix-line",
			// packages_linux.go:346-348 unconditionally skips any line starting with
			// "Last metadata"/"Updating"/"Repositories", by prefix — the suffix
			// (extra) cannot affect that.
			build: func(extra string) seamContent {
				c := d
				c.dnfLine2 = c.dnfLine2 + "\nLast metadata expiration check: " + oneLine(extra)
				return c
			},
			producedOK: dnfProducedData,
		},
		{
			seam: "dnf", kind: "append-unread-trailing-token",
			// Both DNF4 (fields[1],fields[2]) and DNF5 (fields[2],fields[3]) branches
			// (packages_linux.go:355-367) only ever read up to fields[3]; anything
			// appended after is never indexed, regardless of content.
			build: func(extra string) seamContent {
				c := d
				c.dnfLine1 = c.dnfLine1 + " " + oneLine(extra)
				return c
			},
			producedOK: dnfProducedData,
		},
		{
			seam: "thermal", kind: "reorder-zones",
			// readThermalZone (thermal_linux.go:127-146) takes the pure running MAX
			// of tempC across the glob's match list — commutative over any
			// permutation of the SAME value set.
			build: func(extra string) seamContent {
				c := d
				if len(extra)%2 == 0 {
					c.thermalZone0, c.thermalZone1 = reversed2(c.thermalZone0, c.thermalZone1)
				}
				return c
			},
			producedOK: thermalProducedData,
		},
		{
			seam: "thermal", kind: "whitespace-around-value",
			// thermal_linux.go:137 strconv.ParseFloat(strings.TrimSpace(...)) — only
			// leading/trailing whitespace is stripped before parsing.
			build: func(extra string) seamContent {
				c := d
				ws := onlyWhitespace(extra)
				c.thermalZone0 = ws + c.thermalZone0 + ws
				return c
			},
			producedOK: thermalProducedData,
		},
		{
			seam: "edac", kind: "reorder-controllers",
			// readEDACCountsFrom (edac_linux.go:53-54) sums corrected/uncorrected
			// with `+=` across mc* entries in ReadDir order — commutative.
			build: func(extra string) seamContent {
				c := d
				if len(extra)%2 == 0 {
					c.edacDirs = []string{"mc1", "mc0"}
				}
				return c
			},
			producedOK: edacProducedData,
		},
		{
			seam: "edac", kind: "decoy-directory-entry",
			// The "x-" prefix guarantees the decoy never matches
			// strings.HasPrefix(e, "mc") (edac_linux.go:37), so it is filtered before
			// anything else ever inspects it.
			build: func(extra string) seamContent {
				c := d
				c.edacDirs = []string{"mc0", "mc1", "x-" + oneLine(extra)}
				return c
			},
			producedOK: edacProducedData,
		},
		{
			seam: "edac", kind: "whitespace-around-counter",
			// readEDACCounter (edac_linux.go:64) strconv.ParseInt(strings.TrimSpace(...)).
			build: func(extra string) seamContent {
				c := d
				ws := onlyWhitespace(extra)
				c.edacMC0CE = ws + c.edacMC0CE + ws
				return c
			},
			producedOK: edacProducedData,
		},
		{
			seam: "meminfo", kind: "reorder-lines",
			// parseMeminfo (memory.go:36-55) populates a map keyed by trimmed key
			// name — line order cannot affect the resulting map for a set of
			// distinct keys.
			build: func(extra string) seamContent {
				c := d
				lines := append([]string(nil), c.meminfoLines...)
				if len(extra)%2 == 0 {
					for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
						lines[i], lines[j] = lines[j], lines[i]
					}
				}
				c.meminfoLines = lines
				return c
			},
			producedOK: meminfoProducedData,
		},
		{
			seam: "meminfo", kind: "append-unknown-key",
			// memory.go only ever looks up specific exact key names (m["MemTotal"],
			// etc, an exact map-key match) — "ZZZ_FUZZ_" can never equal one of
			// those, regardless of what follows it.
			build: func(extra string) seamContent {
				c := d
				lines := append([]string(nil), c.meminfoLines...)
				lines = append(lines, "ZZZ_FUZZ_UNKNOWN: "+oneLine(extra))
				c.meminfoLines = lines
				return c
			},
			producedOK: meminfoProducedData,
		},
		{
			seam: "meminfo", kind: "append-malformed-line",
			// memory.go:41-44: SplitN(line, ":", 2) with len(parts)!=2 is skipped —
			// guaranteed for any line with zero colons.
			build: func(extra string) seamContent {
				c := d
				lines := append([]string(nil), c.meminfoLines...)
				lines = append(lines, noColon(oneLine(extra)))
				c.meminfoLines = lines
				return c
			},
			producedOK: meminfoProducedData,
		},
		{
			seam: "loadavg", kind: "append-trailing-noise",
			// parseLoadAvg (cpu.go:48-67) only reads fields[0..2] from the FIRST
			// bufio.Scanner line; sysctl.go's readTaskCount only reads fields[3].
			// Anything appended after the 5 real tokens shifts neither.
			build: func(extra string) seamContent {
				c := d
				c.loadavg = c.loadavg + " " + oneLine(extra)
				return c
			},
			producedOK: loadavgProducedData,
		},
		{
			seam: "smart", kind: "append-nonverdict-health-line",
			// parseSMARTHealth (disk_linux.go:241-248) returns on the FIRST matching
			// line; the real verdict line is always first here, so anything appended
			// after is never even reached by the loop.
			build: func(extra string) seamContent {
				c := d
				c.smartHealth = c.smartHealth + "\n" + oneLine(extra)
				return c
			},
			producedOK: smartProducedData,
		},
		{
			seam: "smart", kind: "append-unmatched-attr-line",
			// parseSMARTAttributes (disk_linux.go:272-274): colonIdx<0 -> continue.
			// A colon-free line can never match the isSATAFailureAttr check either.
			build: func(extra string) seamContent {
				c := d
				c.smartAttrLine2 = c.smartAttrLine2 + "\n" + noColon(oneLine(extra))
				return c
			},
			producedOK: smartProducedData,
		},
		{
			seam: "smart", kind: "reorder-sata-attr-lines",
			// disk_linux.go:264-265: s.MediaErrors += raw per matching line — pure
			// sum, order-independent, over the SAME two lines.
			build: func(extra string) seamContent {
				c := d
				if len(extra)%2 == 0 {
					c.smartAttrLine1, c.smartAttrLine2 = reversed2(c.smartAttrLine1, c.smartAttrLine2)
				}
				return c
			},
			producedOK: smartProducedData,
		},
	}
}

// ── the fuzz target ────────────────────────────────────────────────────────────────

func FuzzWholeBundleReplayVerdictFlip(f *testing.F) {
	muts := allMutations()

	// POSITIVE CONTROL — run once, before f.Fuzz, exactly as this task's design
	// requires: the unmutated baseline must yield a non-trivial verdict AND every
	// one of the six seams must have actually produced data.
	baseBundle := buildBundleFrom(seamDefaults())
	baseResults, baseInsights, _ := replayBundle(baseBundle, false, true, false, false)
	baseVerdict := verdictClass(baseInsights)
	if baseVerdict == 0 {
		f.Fatalf("positive control: baseline bundle yielded verdict OK (0) — expected a non-trivial WARN verdict (Important dnf advisories + non-zero SMART MediaErrors), got a healthy result")
	}
	for _, m := range muts {
		if !m.producedOK(baseResults) {
			f.Fatalf("positive control: seam %q produced no data on the unmutated baseline — the harness would be vacuous for every mutation of this seam", m.seam)
		}
	}

	for i := range muts {
		f.Add(uint8(i), "")
		f.Add(uint8(i), "\n\n\n")
	}
	f.Add(uint8(0), "some fuzzed noise \x00\t\n")

	f.Fuzz(func(t *testing.T, selRaw uint8, extra string) {
		m := muts[int(selRaw)%len(muts)]
		c := m.build(extra)
		b := buildBundleFrom(c)

		var results []runner.Result
		var insights []models.Insight
		start := time.Now()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC in whole-bundle replay pipeline (seam=%s kind=%s extra=%q): %v", m.seam, m.kind, extra, r)
				}
			}()
			results, insights, _ = replayBundle(b, false, true, false, false)
		}()
		if elapsed := time.Since(start); elapsed > wholeBundleWorkCeiling {
			t.Fatalf("BOUNDED WORK: whole-bundle replay took %s (> %s) under seam=%s kind=%s", elapsed, wholeBundleWorkCeiling, m.seam, m.kind)
		}

		// Per-iteration vacuity guard: this specific mutation must not have
		// silently dropped the seam's own data (a mutation that broke the seam
		// entirely would trivially "not flip" a verdict it no longer contributes to).
		if !m.producedOK(results) {
			t.Fatalf("seam %q (mutation %q) produced no data after mutation (extra=%q) — the mutation broke data collection for this seam instead of staying neutral", m.seam, m.kind, extra)
		}

		if got := verdictClass(insights); got != baseVerdict {
			t.Fatalf("VERDICT FLIP under seam=%s mutation=%s (extra=%q): base=%d got=%d — a provably verdict-neutral mutation changed the overall verdict class",
				m.seam, m.kind, extra, baseVerdict, got)
		}
	})
}
