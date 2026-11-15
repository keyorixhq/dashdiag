//go:build linux

package cmd

// DD2 capture-replay sweep (task DD2, fuzz/dd2-capture-replay).
//
// This is a TEST-ONLY harness, not product code. It drives the committed replay
// seam (`dsd replay`, i.e. loadBundle -> replayBundle -> render) over a directory
// of real `dsd capture --raw` bundles and emits a capture x check verdict matrix
// plus the DD2 oracles (determinism, anti-false-OK mutation robustness). The
// bundles are NOT committed (they carry real host data); the harness therefore
// SKIPS unless DD2_CAPTURE_DIR points at a readable directory of *.tar.gz, so it
// is green in CI and only does real work on a host that stages the captures.
//
// What this sweep does NOT verify: a capture is a snapshot of ONE machine at ONE
// instant, not a specification. A verdict matching the host at capture time says
// nothing about other configurations of the same distro, nor that the verdict is
// the "right" one -- only that replay reproduces it. See
// docs/fuzz/dd2-capture-replay.md.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/source"
	"github.com/keyorixhq/dashdiag/internal/testutil/srcpath"
)

// dd2CapParmOnce caps GOMAXPROCS from inside the test binary (the DD2 runtime
// rules require GOMAXPROCS=2, but this harness cannot set a shell env var — the
// permission sandbox refuses `VAR=val go test`). Called by the sweep and the
// mutation fuzz target so each worker process stays within the shared-host budget.
var dd2CapParmOnce sync.Once

func dd2CapParallelism() {
	dd2CapParmOnce.Do(func() {
		if runtime.GOMAXPROCS(0) > 2 {
			runtime.GOMAXPROCS(2)
		}
	})
}

// dd2RepoRoot returns the repository root (for committed-fixture paths).
func dd2RepoRoot() string { return srcpath.RepoRoot() }

// baseName returns a capture/fixture basename without the .tar.gz suffix.
func baseName(path string) string {
	b := filepath.Base(path)
	return strings.TrimSuffix(b, ".tar.gz")
}

// dd2CaptureDirPath resolves the staged-captures dir from DD2_CAPTURE_DIR, or
// from a gitignored scratch pointer file (.scratch/dd2-capture-dir) when the
// env var can't be set. Returns "" when neither is present.
func dd2CaptureDirPath() string {
	if d := os.Getenv("DD2_CAPTURE_DIR"); d != "" {
		return d
	}
	for _, p := range []string{
		filepath.Join(".scratch", "dd2-capture-dir"),
		filepath.Join("..", ".scratch", "dd2-capture-dir"),
	} {
		if data, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(data)); s != "" {
				return s
			}
		}
	}
	return ""
}

// dd2CaptureDir returns the staged-captures directory, or skips the test when it
// is unset/absent. Never fails: a missing dir is "nothing staged here", not a bug.
func dd2CaptureDir(t *testing.T) string {
	t.Helper()
	dir := dd2CaptureDirPath()
	if dir == "" {
		t.Skip("no capture dir — set DD2_CAPTURE_DIR or write .scratch/dd2-capture-dir (bundles are not committed)")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("DD2_CAPTURE_DIR %q unreadable: %v", dir, err)
	}
	if len(ents) == 0 {
		t.Skipf("DD2_CAPTURE_DIR %q is empty", dir)
	}
	return dir
}

// dd2OutDir is where the matrix/report artifacts are written (scratch, gitignored).
func dd2OutDir(t *testing.T) string {
	t.Helper()
	out := os.Getenv("DD2_OUT")
	if out == "" {
		out = filepath.Join("..", ".scratch", "out")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatalf("mkdir DD2_OUT %q: %v", out, err)
	}
	return out
}

func dd2ListCaptures(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read capture dir: %v", err)
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".tar.gz") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

// verdictMap reduces a replay to a name->status map, the same reduction
// scripts/check-replay-fidelity.sh uses (`[.checks[] | {(.name): .status}]`).
func verdictMap(results []runner.Result, insights []models.Insight) map[string]string {
	out := render.BuildJSONOutput(results, insights)
	m := make(map[string]string, len(out.Checks))
	for _, c := range out.Checks {
		m[c.Name] = c.Status
	}
	return m
}

// replayOutcome is one capture's replayed verdict picture.
type replayOutcome struct {
	name          string
	loadErr       error
	panicked      string
	verdict       string // overall CRIT/WARN/OK
	checks        map[string]string
	coverage      render.JSONCoverage
	notApplicable map[string]string // check name -> reason
	gaps          int               // checks flagged not_recorded
}

// replayCapture loads and replays one bundle once, recovering any panic.
func replayCapture(path string) (oc replayOutcome) {
	oc.name = strings.TrimSuffix(filepath.Base(path), ".tar.gz")
	defer func() {
		if r := recover(); r != nil {
			oc.panicked = fmt.Sprintf("%v", r)
		}
	}()
	b, err := loadBundle(path)
	if err != nil {
		oc.loadErr = err
		return oc
	}
	results, insights, _ := replayBundle(b, false, true, false, false)
	jo := render.BuildJSONOutput(results, insights)
	oc.verdict = jo.Verdict
	oc.checks = make(map[string]string, len(jo.Checks))
	for _, c := range jo.Checks {
		oc.checks[c.Name] = c.Status
	}
	oc.coverage = jo.Coverage
	oc.notApplicable = map[string]string{}
	for _, na := range jo.Coverage.NotApplicableChecks {
		oc.notApplicable[na.Name] = na.CoverageReason
	}
	for _, r := range results {
		if r.NotRecorded {
			oc.gaps++
		}
	}
	_ = source.ErrNotRecorded // keep source import honest
	return oc
}

// TestDD2CaptureReplaySweep is the Step-2 verdict matrix + Step-3 oracle-1
// (determinism / no-panic) over every staged capture. Skips without captures.
func TestDD2CaptureReplaySweep(t *testing.T) {
	dd2CapParallelism()
	dir := dd2CaptureDir(t)
	out := dd2OutDir(t)
	captures := dd2ListCaptures(t, dir)
	if len(captures) == 0 {
		t.Skip("no *.tar.gz in DD2_CAPTURE_DIR")
	}

	type row struct {
		oc            replayOutcome
		deterministic bool
	}
	var rows []row
	allChecks := map[string]bool{}

	for _, path := range captures {
		oc := replayCapture(path)
		// Oracle 1: three replays must be byte-identical in their verdict map.
		det := true
		if oc.loadErr == nil && oc.panicked == "" {
			first := oc.checks
			for i := 0; i < 2; i++ {
				again := replayCapture(path)
				if again.panicked != "" || again.loadErr != nil {
					det = false
					break
				}
				if !sameVerdicts(first, again.checks) || again.verdict != oc.verdict {
					det = false
					break
				}
			}
		}
		for c := range oc.checks {
			allChecks[c] = true
		}
		rows = append(rows, row{oc: oc, deterministic: det})
	}

	// ---- summary counts ----
	var cleanReplays, loadFails, panics, nonDet int
	for _, r := range rows {
		switch {
		case r.oc.panicked != "":
			panics++
		case r.oc.loadErr != nil:
			loadFails++
		default:
			cleanReplays++
		}
		if !r.deterministic && r.oc.loadErr == nil && r.oc.panicked == "" {
			nonDet++
		}
	}

	// ---- write the verdict matrix (markdown) ----
	var checkNames []string
	for c := range allChecks {
		checkNames = append(checkNames, c)
	}
	sort.Strings(checkNames)

	var sb strings.Builder
	fmt.Fprintf(&sb, "# DD2 capture-replay verdict matrix\n\n")
	fmt.Fprintf(&sb, "Captures: %d | clean replays: %d | load failures: %d | panics: %d | non-deterministic: %d\n\n",
		len(rows), cleanReplays, loadFails, panics, nonDet)
	fmt.Fprintf(&sb, "Cells: OK / WARN / CRIT / ERROR ; `.` = not in checks[] (not-applicable or not-recorded on this capture).\n\n")

	// header
	sb.WriteString("| capture | verdict | applicable | n/a | not_checked | gaps |")
	for _, c := range checkNames {
		fmt.Fprintf(&sb, " %s |", c)
	}
	sb.WriteString("\n|")
	for i := 0; i < 6+len(checkNames); i++ {
		sb.WriteString("---|")
	}
	sb.WriteString("\n")

	for _, r := range rows {
		oc := r.oc
		status := oc.verdict
		if oc.panicked != "" {
			status = "PANIC"
		} else if oc.loadErr != nil {
			status = "LOAD-ERR"
		}
		fmt.Fprintf(&sb, "| %s | %s | %d | %d | %d | %d |",
			oc.name, status, oc.coverage.Checked, oc.coverage.NotApplicable, oc.coverage.NotChecked, oc.gaps)
		for _, c := range checkNames {
			v := oc.checks[c]
			if v == "" {
				v = "."
			}
			fmt.Fprintf(&sb, " %s |", v)
		}
		sb.WriteString("\n")
	}

	// ---- per-capture not-applicable reasons ----
	sb.WriteString("\n## Not-applicable checks per capture (with reason)\n\n")
	for _, r := range rows {
		if len(r.oc.notApplicable) == 0 {
			continue
		}
		var keys []string
		for k := range r.oc.notApplicable {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(&sb, "- **%s**: ", r.oc.name)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s (%s)", k, r.oc.notApplicable[k]))
		}
		sb.WriteString(strings.Join(parts, ", ") + "\n")
	}

	// ---- load failures / panics detail ----
	sb.WriteString("\n## Load failures / panics\n\n")
	any := false
	for _, r := range rows {
		if r.oc.loadErr != nil {
			fmt.Fprintf(&sb, "- **%s**: load error: %v\n", r.oc.name, r.oc.loadErr)
			any = true
		}
		if r.oc.panicked != "" {
			fmt.Fprintf(&sb, "- **%s**: PANIC: %s\n", r.oc.name, r.oc.panicked)
			any = true
		}
	}
	if !any {
		sb.WriteString("None.\n")
	}

	matrixPath := filepath.Join(out, "verdict-matrix.md")
	if err := os.WriteFile(matrixPath, []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("write matrix: %v", err)
	}
	t.Logf("wrote verdict matrix: %s (%d captures, %d clean, %d load-fail, %d panic, %d non-det)",
		matrixPath, len(rows), cleanReplays, loadFails, panics, nonDet)

	// Oracle 1 is a hard assertion: no panic, no non-determinism.
	for _, r := range rows {
		if r.oc.panicked != "" {
			t.Errorf("PANIC replaying capture %s: %s", r.oc.name, r.oc.panicked)
		}
		if !r.deterministic && r.oc.loadErr == nil && r.oc.panicked == "" {
			t.Errorf("NON-DETERMINISTIC replay for capture %s: three replays disagreed", r.oc.name)
		}
	}
}

// TestDD2CaptureMutationSweep applies the anti-false-OK mutation engine to every
// staged capture (breadth the fuzz target's committed fixtures can't reach) and
// writes every FALSE-OK / panic hit to .scratch/out for triage. Env-gated. It
// FAILS on any hit so a real finding is loud, but its value is the written report.
func TestDD2CaptureMutationSweep(t *testing.T) {
	dd2CapParallelism()
	dir := dd2CaptureDir(t)
	out := dd2OutDir(t)
	captures := dd2ListCaptures(t, dir)

	const kinds = 8
	// Per-capture case budget: every blob gets a rotating kind; the strongest
	// info-removal kinds (truncate-empty=0, garble-digits=2, drop=7) are forced on
	// the first blobs. Bounded so the whole sweep stays ~minutes, not an hour.
	maxCasesPerCapture := 12

	type hit struct {
		capture, check, baseStatus, blob string
		kind                             int
	}
	var hits []hit
	var sb strings.Builder
	fmt.Fprintf(&sb, "# DD2 capture mutation sweep (anti-false-OK over all captures)\n\n")

	var totalCases, capturesSwept int
	for _, path := range captures {
		name := baseName(path)
		b0, err := loadBundle(path)
		if err != nil {
			fmt.Fprintf(&sb, "- SKIP %s: load error: %v\n", name, err)
			continue
		}
		baseDir := t.TempDir()
		if err := b0.Save(baseDir); err != nil {
			fmt.Fprintf(&sb, "- SKIP %s: save error: %v\n", name, err)
			continue
		}
		baseTree, err := readTree(baseDir)
		if err != nil {
			continue
		}
		blobs := blobList(baseTree)
		if len(blobs) == 0 {
			continue
		}
		baseline := func() map[string]string {
			b, e := source.Load(baseDir)
			if e != nil {
				return nil
			}
			r, i, _ := replayBundle(b, false, true, false, false)
			return verdictMap(r, i)
		}()
		baselineNonOK := map[string]string{}
		for n, s := range baseline {
			if s != "OK" {
				baselineNonOK[n] = s
			}
		}
		if len(baselineNonOK) == 0 {
			fmt.Fprintf(&sb, "- %s: no non-OK baseline check (nothing to protect)\n", name)
			continue
		}
		capturesSwept++

		// Build bounded case list.
		type dcase struct{ bi, kind int }
		seen := map[dcase]bool{}
		var cases []dcase
		add := func(bi, kind int) {
			if len(cases) >= maxCasesPerCapture {
				return
			}
			c := dcase{bi % len(blobs), kind % kinds}
			if !seen[c] {
				seen[c] = true
				cases = append(cases, c)
			}
		}
		for _, k := range []int{0, 2, 7} { // strongest info-removal, on the first blobs
			for bi := 0; bi < len(blobs); bi++ {
				add(bi, k)
			}
		}
		for bi := 0; bi < len(blobs); bi++ {
			add(bi, bi) // rotating kind
		}

		for _, c := range cases {
			totalCases++
			dmgDir := t.TempDir()
			dd2ApplyDamage(dmgDir, baseTree, blobs, c.bi, c.kind, "")
			var damaged map[string]string
			var panicked string
			func() {
				defer func() {
					if r := recover(); r != nil {
						panicked = fmt.Sprintf("%v", r)
					}
				}()
				b, e := source.Load(dmgDir)
				if e != nil {
					return
				}
				r, i, _ := replayBundle(b, false, true, false, false)
				damaged = verdictMap(r, i)
			}()
			if panicked != "" {
				fmt.Fprintf(&sb, "- PANIC %s blob=%s kind=%d: %s\n", name, blobs[c.bi], c.kind, panicked)
				t.Errorf("PANIC %s blob=%s kind=%d: %s", name, blobs[c.bi], c.kind, panicked)
				continue
			}
			for ck, bs := range baselineNonOK {
				if got, ok := damaged[ck]; ok && got == "OK" {
					hits = append(hits, hit{name, ck, bs, blobs[c.bi], c.kind})
				}
			}
		}
	}

	fmt.Fprintf(&sb, "\nCaptures swept (with non-OK baseline): %d | total damage cases: %d | non-OK→OK candidates: %d\n\n",
		capturesSwept, totalCases, len(hits))
	sb.WriteString("A non-OK→OK candidate is NOT automatically a defect: truncating a legitimately-\n")
	sb.WriteString("optional file to empty can make a check honestly OK (empty = no finding). Each is\n")
	sb.WriteString("classified by hand in docs/fuzz/dd2-capture-replay.md. kind: 0=truncate-empty\n")
	sb.WriteString("1=truncate-half 2=garble-digits 3=uppercase 4=whitespace 5=prepend-noise\n")
	sb.WriteString("6=append-noise 7=drop-entry.\n\n")
	if len(hits) == 0 {
		sb.WriteString("No candidates: no information-destroying mutation turned a non-OK check into OK on any capture.\n")
	} else {
		// Group by (check, kind) to spot systematic patterns vs one-offs.
		byKey := map[string]int{}
		for _, h := range hits {
			byKey[fmt.Sprintf("%s kind=%d", h.check, h.kind)]++
		}
		sb.WriteString("## non-OK→OK candidates (triage)\n\n")
		for _, h := range hits {
			fmt.Fprintf(&sb, "- %s: check %q was %s, became OK after blob=%s kind=%d\n",
				h.capture, h.check, h.baseStatus, h.blob, h.kind)
		}
		sb.WriteString("\n### grouped by check+kind\n\n")
		var keys []string
		for k := range byKey {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&sb, "- %s: %d\n", k, byKey[k])
		}
	}
	p := filepath.Join(out, "mutation-sweep.md")
	if err := os.WriteFile(p, []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("write mutation sweep: %v", err)
	}
	t.Logf("wrote mutation sweep: %s (%d captures, %d cases, %d candidates)", p, capturesSwept, totalCases, len(hits))
	// Candidates are report-only (triaged by hand); only a PANIC is a hard failure.
}

// dd2SiblingGroup is a set of captures expected to agree on semantically
// identical facts. mustMatch=true means the pair is the SAME capture session
// differing only in a verdict-neutral way (sanitize-vs-raw), so any verdict
// divergence is a DEFECT and asserted hard; mustMatch=false groups are distro
// siblings whose divergences are tabulated and classified, not asserted.
type dd2SiblingGroup struct {
	name      string
	members   []string // capture basenames (no .tar.gz)
	mustMatch bool
	note      string
}

func dd2SiblingGroups() []dd2SiblingGroup {
	return []dd2SiblingGroup{
		// Sanitize-vs-raw twins: identical host+session, identifiers redacted only.
		// Verdicts MUST be identical — sanitize must not move a verdict.
		{"fcos44 sanitize/raw", []string{"fcos44-vmware-20260629", "fcos44-vmware-20260629-sanitized"}, true,
			"sanitize --identifiers must be verdict-neutral"},
		{"ubuntumin sanitize/raw", []string{"dsd-raw-ubuntumin-20260624-212600", "dsd-raw-ubuntumin-20260624-212600-sanitized"}, true,
			"sanitize --identifiers must be verdict-neutral"},
		// Same host, two capture dates / a postfix install — mostly agree.
		{"oci oraclelinux9 two dates", []string{"oci-a1-oraclelinux9-20260706", "oci-a1-oraclelinux9-20260716"}, false,
			"same OCI Ampere host, 10 days apart"},
		{"leapmicro base/postfix", []string{"leapmicro-vmware-20260628", "leapmicro-vmware-postfix-20260629"}, false,
			"postfix install changes service/mail posture only"},
		{"sles16 vmware full/kernelfix", []string{"sles16-vmware-vcd-full-20260630", "sles16-vmware-vcd-kernelfix-20260630"}, false,
			"kernel fix variant"},
		// Distro siblings (different hosts, same family).
		{"debian231 broken/fixed", []string{"dsd-debian231", "dsd-debian231-fixed"}, false,
			"before/after a fix — divergence is the point"},
		{"oraclelinux9 vmware variants", []string{"oraclelinux9-vmware-vcd-20260629", "oraclelinux9-vmware-vcd-full-20260629"}, false,
			"same distro, terse vs full capture"},
		{"kubernetes flavours (debian)", []string{"k0s-debian-20260701", "kubeadm-debian-20260701", "rke2-debian-20260701"}, false,
			"three k8s distributions on Debian"},
	}
}

// TestDD2SiblingParity tabulates sibling agreement and hard-asserts the
// sanitize-vs-raw twins are verdict-identical. Env-gated (needs the captures).
func TestDD2SiblingParity(t *testing.T) {
	dd2CapParallelism()
	dir := dd2CaptureDir(t)
	out := dd2OutDir(t)

	// Replay every capture named in any group once; cache the verdict maps.
	verd := map[string]map[string]string{}
	loadOf := func(name string) map[string]string {
		if m, ok := verd[name]; ok {
			return m
		}
		oc := replayCapture(filepath.Join(dir, name+".tar.gz"))
		verd[name] = oc.checks // nil if load/panic
		return oc.checks
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "# DD2 sibling parity\n\n")
	fmt.Fprintf(&sb, "Compares sibling captures on applicable check-IDs and verdicts of identical facts.\n")
	fmt.Fprintf(&sb, "`mustMatch` groups (sanitize/raw twins) are asserted identical; others are classified.\n\n")

	for _, g := range dd2SiblingGroups() {
		fmt.Fprintf(&sb, "## %s\n\n%s. Members: %s\n\n", g.name, g.note, strings.Join(g.members, ", "))
		// Pairwise against the first present member.
		var base string
		var baseM map[string]string
		for _, m := range g.members {
			vm := loadOf(m)
			if vm == nil {
				fmt.Fprintf(&sb, "- SKIP %s (absent/failed to replay)\n", m)
				continue
			}
			if baseM == nil {
				base, baseM = m, vm
				continue
			}
			diffs := verdictDiffs(baseM, vm)
			onlyA, onlyB := checkSetDiff(baseM, vm)
			if len(diffs) == 0 && len(onlyA) == 0 && len(onlyB) == 0 {
				fmt.Fprintf(&sb, "- %s vs %s: IDENTICAL (%d checks)\n", base, m, len(baseM))
			} else {
				fmt.Fprintf(&sb, "- %s vs %s: %d verdict diffs; check-set only-%s=%v only-%s=%v\n",
					base, m, len(diffs), base, onlyA, m, onlyB)
				for _, d := range diffs {
					fmt.Fprintf(&sb, "    - %s\n", d)
				}
			}
			if g.mustMatch {
				if len(diffs) != 0 || len(onlyA) != 0 || len(onlyB) != 0 {
					t.Errorf("SIBLING-PARITY DEFECT (%s): %s and %s must be verdict-identical (sanitize is verdict-neutral) but differ: diffs=%v onlyA=%v onlyB=%v",
						g.name, base, m, diffs, onlyA, onlyB)
				}
			}
		}
		sb.WriteString("\n")
	}

	p := filepath.Join(out, "sibling-parity.md")
	if err := os.WriteFile(p, []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("write parity: %v", err)
	}
	t.Logf("wrote sibling parity: %s", p)
}

// verdictDiffs lists "check: a!=b" for checks present in both with differing status.
func verdictDiffs(a, b map[string]string) []string {
	var out []string
	var keys []string
	for k := range a {
		if _, ok := b[k]; ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		if a[k] != b[k] {
			out = append(out, fmt.Sprintf("%s: %s vs %s", k, a[k], b[k]))
		}
	}
	return out
}

// checkSetDiff returns checks applicable only in a, and only in b.
func checkSetDiff(a, b map[string]string) (onlyA, onlyB []string) {
	for k := range a {
		if _, ok := b[k]; !ok {
			onlyA = append(onlyA, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			onlyB = append(onlyB, k)
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	return onlyA, onlyB
}

func sameVerdicts(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
