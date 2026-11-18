//go:build unix

package cis

// XD1 Target A — CIS file-reading check helpers must be FAIL-CLOSED.
//
// The shared file-reading helpers in rules.go that take an explicit path —
// checkSysctl, checkSysctlGE, checkFilePerm, checkBannerContent,
// checkLoginDefsField — are the common choke points behind dozens of CIS rules.
// The product claim XD1 fuzzes here is the one in models.CISResult.Unverified's
// doc comment: a check that could not read or parse its input must report a
// non-PASS (SKIP/FAIL/unverified) — it must never certify compliance ("PASS")
// off missing or unparseable data. A false PASS on unreadable input is a
// false-clean compliance verdict.
//
// Oracle (per fuzzed input, for every helper):
//   1. ABSENT INPUT ⇒ NEVER PASS. Called with a path that does not exist, the
//      helper must return a status other than CISPass. Airtight and universal.
//   2. PASS ⇒ INDEPENDENTLY COMPLIANT. For the helpers whose compliance
//      predicate can be re-derived from the CIS spec (sysctl exact-match,
//      sysctl >=N, permission bitmask, banner non-empty+no-fingerprint) a
//      from-scratch reimplementation decides the correct verdict and must agree
//      with the helper on whether the input is a PASS. This catches a helper
//      that PASSes on content that is NOT actually compliant (false-clean on
//      garbage/partial input). The reimplementation is written from the spec,
//      not copied from rules.go, so the two cannot share a blind spot.
//   3. READ-ONLY. The helpers only read; the DL1 resource fingerprint asserts
//      the on-disk temp tree is byte-identical before/after the batch.
//
// checkLoginDefsField is held to (1) plus a weaker structural check (a PASS must
// correspond to the field actually appearing in the file) rather than full
// content-equivalence, because its documented behaviour deliberately ignores
// fmt.Sscanf parse errors (//nolint:errcheck in rules.go) — asserting a stricter
// parse would contradict intended behaviour. The trailing-garbage fail-open that
// leaves is reported as a lead in the XD1 report, not asserted here.
//
// The mount helpers (checkMountOption/checkSeparateMountPoint) read the package
// var procMountsPath rather than a path argument; mutating it under -parallel 2
// fuzz workers would be a data race, so they are covered by the serialized
// deterministic TestXD1MountHelpersFailClosed instead of this fuzz target.
//
// Resource meters enabled: TotalAlloc + wall time (resource.Check) and the unix
// filesystem fingerprint (resource.AssertUnchanged). Not metered: file
// descriptors (each helper opens at most one short-lived fd) and goroutines
// (these helpers spawn none).

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// dummyRule is the Rule the helpers stamp onto their CISResult. Only Status
// matters to the fail-closed oracle.
func dummyRule() Rule { return Rule{ID: "xd1", Framework: cisBenchCIS, Level: 1, Section: "xd1"} }

// failClosedViolation returns a non-empty description when `got` breaches the
// fail-closed contract, or "" when it is sound. A PASS is a violation iff the
// independent oracle says the input is not compliant; any non-PASS is sound
// (fail-closed may be conservative). Single assertion point shared by the fuzz
// target, the seed test and the red/green proof.
func failClosedViolation(got models.CISStatus, expectPass bool) string {
	if got == models.CISPass && !expectPass {
		return "reported PASS on input the independent oracle rejects (false-clean)"
	}
	return ""
}

// ---- independent (spec-derived) oracles -----------------------------------

func oracleSysctlExact(content, wantVal string) bool {
	return strings.TrimSpace(content) == wantVal
}

func oracleSysctlGE(content string, minVal int) bool {
	v, err := strconv.Atoi(strings.TrimSpace(content))
	if err != nil {
		return false // non-integer is unverifiable, never compliant
	}
	return v >= minVal
}

func oracleFilePerm(mode, maxMode os.FileMode) bool {
	return mode.Perm()&^maxMode == 0
}

func oracleBanner(content string) bool {
	if strings.TrimSpace(content) == "" {
		return false
	}
	for _, seq := range []string{`\s`, `\m`, `\r`, `\v`, `\u`} {
		if strings.Contains(content, seq) {
			return false
		}
	}
	return true
}

// loginDefsHasField reports whether content has an uncommented line whose first
// token equals field — the structural precondition a checkLoginDefsField PASS
// must satisfy (it can only PASS a field it matched).
func loginDefsHasField(content, field string) bool {
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		ff := strings.Fields(t)
		if len(ff) >= 1 && ff[0] == field {
			return true
		}
	}
	return false
}

func xd1WriteFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// runPathHelpers drives every path-parameterised helper on the fuzzed inputs and
// returns the list of fail-closed violations. It assumes the "content" and
// "perm" fixture files already exist under dir (written before fingerprinting),
// so the batch itself performs zero writes and the read-only fingerprint holds.
func runPathHelpers(dir, content, wantVal string, minVal int, modeBits uint16) []string {
	r := dummyRule()
	var viol []string
	add := func(name, msg string) {
		if msg != "" {
			viol = append(viol, name+": "+msg)
		}
	}
	absent := filepath.Join(dir, "does-not-exist")
	cp := filepath.Join(dir, "content")
	fp := filepath.Join(dir, "perm")
	maxDaysFails := func(days int) bool { return days > 365 || days == 0 }

	// absent-input: every helper must be non-PASS
	add("sysctl/absent", failClosedViolation(checkSysctl(r, absent, wantVal, "f", "x").Status, false))
	add("sysctlGE/absent", failClosedViolation(checkSysctlGE(r, absent, minVal, "f", "x").Status, false))
	add("filePerm/absent", failClosedViolation(checkFilePerm(r, absent, 0o644, "x").Status, false))
	add("banner/absent", failClosedViolation(checkBannerContent(r, absent, "x").Status, false))
	add("loginDefs/absent", failClosedViolation(
		checkLoginDefsField(r, absent, "PASS_MAX_DAYS", maxDaysFails, "f", "x", "n", "x").Status, false))

	// present-input: PASS must match the independent oracle
	add("sysctl/present", failClosedViolation(
		checkSysctl(r, cp, wantVal, "f", "x").Status, oracleSysctlExact(content, wantVal)))
	add("sysctlGE/present", failClosedViolation(
		checkSysctlGE(r, cp, minVal, "f", "x").Status, oracleSysctlGE(content, minVal)))
	add("banner/present", failClosedViolation(
		checkBannerContent(r, cp, "x").Status, oracleBanner(content)))

	if checkLoginDefsField(r, cp, "PASS_MAX_DAYS", maxDaysFails, "f", "x", "n", "x").Status == models.CISPass &&
		!loginDefsHasField(content, "PASS_MAX_DAYS") {
		add("loginDefs/present", "PASS without the field appearing in the file")
	}

	mode := os.FileMode(modeBits) & os.ModePerm
	add("filePerm/present", failClosedViolation(checkFilePerm(r, fp, 0o644, "x").Status, oracleFilePerm(mode, 0o644)))

	return viol
}

func FuzzCISFileHelpersFailClosed(f *testing.F) {
	f.Add("265", "265", 0, uint16(0o644))
	f.Add("PASS_MAX_DAYS 365\n", "1", 0, uint16(0o640))
	f.Add("", "0", 0, uint16(0o777))
	f.Add("abc", "7", 7, uint16(0o600))
	f.Add("  12\n", "1", 1, uint16(0o700))
	f.Add("Authorized users only\n", "1", 1, uint16(0o644))

	f.Fuzz(func(t *testing.T, content, wantVal string, minVal int, modeBits uint16) {
		dir, err := os.MkdirTemp("", "xd1-cis-")
		if err != nil {
			t.Fatalf("mkdtemp: %v", err)
		}
		defer os.RemoveAll(dir)

		var viol []string
		before := ""
		resource.Check(t, len(content), 512, func() {
			_ = xd1WriteFile(t, dir, "content", content)
			fp := xd1WriteFile(t, dir, "perm", "x")
			_ = os.Chmod(fp, os.FileMode(modeBits)&os.ModePerm)
			before = resource.Fingerprint(t, dir)
			viol = runPathHelpers(dir, content, wantVal, minVal, modeBits)
		})
		resource.AssertUnchanged(t, dir, before)
		if len(viol) > 0 {
			t.Fatalf("fail-closed violation(s): %s", strings.Join(viol, "; "))
		}
	})
}

// --- deterministic seed guard (watched passing) ----------------------------

// TestXD1FileHelpersFailClosedSeeds exercises each helper's absent / compliant /
// violating / garbage cases so the oracle is run on every `go test ./internal/cis`
// even without -fuzz.
func TestXD1FileHelpersFailClosedSeeds(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		content string
		wantVal string
		minVal  int
		mode    uint16
	}{
		{"265", "265", 0, 0o644},             // sysctl exact PASS
		{"264", "265", 0, 0o644},             // sysctl exact FAIL
		{"12", "1", 1, 0o640},                // sysctlGE PASS
		{"abc", "1", 1, 0o777},               // sysctlGE non-int → not PASS
		{"", "0", 0, 0o600},                  // banner empty → FAIL, sysctl "" != "0"
		{"Authorized only\n", "x", 0, 0o700}, // banner PASS
	}
	for i, c := range cases {
		sub := filepath.Join(dir, strconv.Itoa(i))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = xd1WriteFile(t, sub, "content", c.content)
		fp := xd1WriteFile(t, sub, "perm", "x")
		_ = os.Chmod(fp, os.FileMode(c.mode)&os.ModePerm)
		if viol := runPathHelpers(sub, c.content, c.wantVal, c.minVal, c.mode); len(viol) > 0 {
			t.Errorf("case %d (%q): %s", i, c.content, strings.Join(viol, "; "))
		}
	}
}

// TestXD1FailClosedRedGreen watches the fail-closed oracle actually fire. A
// guard nobody has watched fail is not a guard: a planted "broken" helper that
// PASSes on non-integer input must make failClosedViolation report a breach,
// and the real helper on the same input must not.
func TestXD1FailClosedRedGreen(t *testing.T) {
	const garbage = "not-a-number"
	// GREEN: the real checkSysctlGE returns unverified (not PASS) on non-int.
	dir := t.TempDir()
	cp := xd1WriteFile(t, dir, "content", garbage)
	realStatus := checkSysctlGE(dummyRule(), cp, 1, "f", "x").Status
	if msg := failClosedViolation(realStatus, oracleSysctlGE(garbage, 1)); msg != "" {
		t.Errorf("GREEN: real helper should be fail-closed on %q, got violation: %s (status=%s)", garbage, msg, realStatus)
	}
	// RED: a broken helper that PASSes on garbage must trip the oracle.
	brokenStatus := models.CISPass
	if msg := failClosedViolation(brokenStatus, oracleSysctlGE(garbage, 1)); msg == "" {
		t.Error("RED: oracle failed to flag a broken helper that PASSes on non-integer input")
	}
}

// --- mount helpers: serialized deterministic fail-closed test --------------

var xd1MountMu sync.Mutex

// TestXD1MountHelpersFailClosed covers checkMountOption/checkSeparateMountPoint,
// which read the package var procMountsPath. It mutates that var under a mutex
// (no t.Parallel) rather than fuzzing it concurrently.
func TestXD1MountHelpersFailClosed(t *testing.T) {
	xd1MountMu.Lock()
	defer xd1MountMu.Unlock()
	orig := procMountsPath
	defer func() { procMountsPath = orig }()
	dir := t.TempDir()
	r := dummyRule()

	// absent /proc/mounts → both must be non-PASS (skip)
	procMountsPath = filepath.Join(dir, "no-mounts")
	if s := checkMountOption(r, "/boot", "nosuid", "x").Status; s == models.CISPass {
		t.Errorf("checkMountOption: PASS on absent /proc/mounts (status=%s)", s)
	}
	if s := checkSeparateMountPoint(r, "/boot", "x").Status; s == models.CISPass {
		t.Errorf("checkSeparateMountPoint: PASS on absent /proc/mounts (status=%s)", s)
	}

	// present but mount absent → mountOption skips (not a separate mount) and
	// separateMount FAILs; neither is a false PASS.
	procMountsPath = xd1WriteFile(t, dir, "mounts", "/dev/sda1 / ext4 rw 0 0\n")
	if s := checkSeparateMountPoint(r, "/boot", "x").Status; s == models.CISPass {
		t.Errorf("checkSeparateMountPoint: PASS when /boot is not a separate mount (status=%s)", s)
	}
	// compliant case: /boot present with nosuid → PASS is correct
	procMountsPath = xd1WriteFile(t, dir, "mounts2", "/dev/sda1 /boot ext4 rw,nosuid,nodev 0 0\n")
	if s := checkMountOption(r, "/boot", "nosuid", "x").Status; s != models.CISPass {
		t.Errorf("checkMountOption: want PASS for /boot with nosuid, got %s", s)
	}
}
