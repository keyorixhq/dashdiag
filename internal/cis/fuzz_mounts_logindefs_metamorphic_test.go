package cis

import (
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// knownDefects gates the reference-semantics properties that fail on the
// current code (DS1-F2, DS1-F3, DS1-F4 in docs/findings/2026-11-14-DS1-*.md). They
// stay in the target so a fix can be proven by flipping one env var, without
// breaking the seed-corpus run in CI meanwhile.
func knownDefects() bool { return os.Getenv("DSD_KNOWN_DEFECTS") == "1" }

// mountRuleIDs are every rule that reads /proc/mounts (checkMountOption,
// checkSeparateMountPoint, checkRemovableMediaOption), reached the way
// `dsd cis` reaches them: Evaluate -> Rule.Check.
var mountRuleIDs = []string{
	"1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.13", "1.1.14", "1.1.15", "1.1.16",
	"1.1.19", "1.1.20", "1.1.21", "1.1.23", "1.1.25", "1.1.29", "1.1.30", "1.1.31", "1.1.32",
}

// ruleMountPoints are the mount points those rules look up.
var ruleMountPoints = []string{"/tmp", "/home", "/var", "/var/log/audit"}

func mountVerdicts(t *testing.T, path string, content string) []models.CISStatus {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	out := make([]models.CISStatus, len(mountRuleIDs))
	for i, id := range mountRuleIDs {
		out[i] = ruleByID(id).Check(models.SecurityInfo{}, models.KernelSecurityInfo{}).Status
	}
	return out
}

// FuzzCISMountRulesMetamorphic feeds /proc/mounts content to every CIS rule
// that reads it and checks that rewrites which keep the same mount facts keep
// the same verdicts:
//
//  1. field whitespace: re-joining each line's fields with tabs or runs of
//     spaces;
//  2. option order: reversing every comma-separated option list (options are
//     a set);
//  3. CRLF line endings;
//  4. unrelated mounts: adding a mount line for a mount point no rule looks at
//     (not a rule mount point, not under /media or /mnt), before and after;
//  5. overmount (gated, DS1-F2): adding an EARLIER entry for a rule mount
//     point leaves the effective mount unchanged, because the kernel lists
//     mounts in mount order and the last entry for a path is the one on top.
//     The verdict must follow the visible mount.
//
// What it does NOT verify: that the verdict for a given mount set is the
// right CIS answer (only that equivalent inputs agree), octal escapes such as
// \040 in mount points, bind mounts or mount propagation, and the real
// /proc/mounts on a live host (rules read the file directly; the target
// redirects procMountsPath).
func FuzzCISMountRulesMetamorphic(f *testing.F) {
	for _, s := range []string{
		"/dev/sda1 / ext4 rw 0 0\ntmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n",
		"/dev/sda1 / ext4 rw 0 0\ntmpfs /tmp tmpfs rw,nosuid 0 0\n/dev/sda2 /home ext4 rw,nodev 0 0\n",
		"/dev/sdb1 /media/usb vfat rw,nosuid,nodev 0 0\n/dev/sr0 /mnt/cd iso9660 ro 0 0\n",
		"/dev/sda3 /var xfs rw,nodev,nosuid 0 0\n/dev/sda4 /var/log/audit xfs rw 0 0\n",
		"tmpfs /tmp tmpfs rw,nodev,nosuid,noexec 0 0\ntmpfs /tmp tmpfs rw 0 0\n",
		"",
		"garbage\n/tmp\n a b\n",
	} {
		f.Add(s)
	}
	dir := f.TempDir()
	path := filepath.Join(dir, "mounts")
	orig := procMountsPath
	procMountsPath = path
	f.Cleanup(func() { procMountsPath = orig })

	f.Fuzz(func(t *testing.T, mounts string) {
		if len(mounts) > 4096 {
			return
		}
		base := mountVerdicts(t, path, mounts)
		check := func(name, variant string) {
			t.Helper()
			if got := mountVerdicts(t, path, variant); !slices.Equal(got, base) {
				t.Fatalf("%s changes CIS mount verdicts\n rules  %v\n before %v\n after  %v\n input  %q\n variant %q",
					name, mountRuleIDs, base, got, mounts, variant)
			}
		}
		lines := strings.Split(mounts, "\n")
		rejoin := func(sep string) string {
			out := make([]string, len(lines))
			for i, l := range lines {
				out[i] = strings.Join(strings.Fields(l), sep)
			}
			return strings.Join(out, "\n")
		}
		check("tab-separated fields", rejoin("\t"))
		check("multi-space fields", rejoin("   "))

		rev := make([]string, len(lines))
		for i, l := range lines {
			fs := strings.Fields(l)
			if len(fs) >= 4 {
				opts := strings.Split(fs[3], ",")
				slices.Reverse(opts)
				fs[3] = strings.Join(opts, ",")
			}
			rev[i] = strings.Join(fs, " ")
		}
		check("reversed option order", strings.Join(rev, "\n"))
		check("CRLF line endings", strings.ReplaceAll(mounts, "\n", "\r\n"))
		const unrelated = "proc /proc proc rw,nosuid,nodev,noexec 0 0"
		check("unrelated mount appended", mounts+"\n"+unrelated+"\n")
		check("unrelated mount prepended", unrelated+"\n"+mounts)

		if !knownDefects() {
			return
		}
		for _, mp := range ruleMountPoints {
			for i, l := range lines {
				fs := strings.Fields(l)
				if len(fs) >= 4 && fs[1] == mp {
					shadow := "tmpfs " + mp + " tmpfs rw,nodev,nosuid,noexec 0 0"
					v := slices.Concat(lines[:i], []string{shadow}, lines[i:])
					check("overmount below "+mp+" (shadowed entry, DS1-F2)", strings.Join(v, "\n"))
					break
				}
			}
		}
	})
}

// loginDefsRules are the password-aging rules that read /etc/login.defs via
// checkLoginDefsField, plus 5.4.3 (ENCRYPT_METHOD) which parses it inline.
// lo/hi is the compliant integer range stated in each rule's description
// (both zero: not a numeric rule).
var loginDefsRules = []struct {
	id, field string
	lo, hi    int
}{
	{"5.4.1", "PASS_MAX_DAYS", 1, 365}, {"5.4.4", "PASS_MIN_DAYS", 1, math.MaxInt}, {"5.4.6", "PASS_WARN_AGE", 7, math.MaxInt},
	{"V-238380", "PASS_MAX_DAYS", 1, 60}, {"V-238382", "PASS_MIN_DAYS", 1, math.MaxInt}, {"V-238383", "PASS_WARN_AGE", 7, math.MaxInt},
	{"5.4.3", "ENCRYPT_METHOD", 0, 0},
}

func loginDefsVerdicts(t *testing.T, path, content string) []models.CISStatus {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	out := make([]models.CISStatus, len(loginDefsRules))
	for i, r := range loginDefsRules {
		out[i] = ruleByID(r.id).Check(models.SecurityInfo{}, models.KernelSecurityInfo{}).Status
	}
	return out
}

// FuzzCISLoginDefsMetamorphic feeds /etc/login.defs content to the
// password-aging and hashing rules. Oracles:
//
//  1. comments and blank lines: inserting "#"-comment lines (including ones
//     that name the field) and blank lines anywhere keeps every verdict;
//  2. field whitespace: re-joining fields with tabs keeps every verdict;
//  3. reference verdict for PASS (false-OK guard; gated, DS1-F4, found by
//     this target in under a second): when a password-aging
//     rule PASSES, the line that decides it must hold a strict decimal
//     integer (strconv.Atoi) inside the compliant range the rule's own
//     description states (PASS_MAX_DAYS 1..365, STIG 1..60; PASS_MIN_DAYS >= 1;
//     PASS_WARN_AGE >= 7). shadow-utils' getdef_num rejects a value such as
//     "7days" and falls back to a non-compliant default, and a negative
//     PASS_MAX_DAYS disables password expiry altogether;
//  4. last occurrence wins (gated, DS1-F3): shadow-utils' def_load keeps the
//     LAST assignment of a key, so appending a later line for a field changes
//     the effective value; a verdict must follow the appended value. Checked
//     by appending non-compliant lines and requiring that no rule PASSES.
//
// What it does NOT verify: hex/octal value spellings (shadow's base handling
// is not modelled), /etc/login.defs.d drop-ins, PAM overrides of these
// values, or whether CIS thresholds themselves are right.
func FuzzCISLoginDefsMetamorphic(f *testing.F) {
	for _, s := range []string{
		"PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\nENCRYPT_METHOD SHA512\n",
		"PASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\nPASS_WARN_AGE\t7\nENCRYPT_METHOD MD5\n",
		"# PASS_MAX_DAYS 90\n\nPASS_MAX_DAYS 400\n",
		"PASS_WARN_AGE 14\nPASS_WARN_AGE 3\n",
		"PASS_MIN_DAYS\n",
		"",
	} {
		f.Add(s)
	}
	path := filepath.Join(f.TempDir(), "login.defs")
	orig := loginDefsPath
	loginDefsPath = path
	f.Cleanup(func() { loginDefsPath = orig })

	f.Fuzz(func(t *testing.T, defs string) {
		if len(defs) > 4096 {
			return
		}
		base := loginDefsVerdicts(t, path, defs)
		check := func(name, variant string) {
			t.Helper()
			if got := loginDefsVerdicts(t, path, variant); !slices.Equal(got, base) {
				t.Fatalf("%s changes login.defs verdicts\n before %v\n after  %v\n input  %q\n variant %q", name, base, got, defs, variant)
			}
		}
		lines := strings.Split(defs, "\n")
		withComments := make([]string, 0, 3*len(lines))
		tabbed := make([]string, len(lines))
		for i, l := range lines {
			withComments = append(withComments, "# PASS_MAX_DAYS 1 PASS_MIN_DAYS 1 PASS_WARN_AGE 7", "", l)
			tabbed[i] = strings.Join(strings.Fields(l), "\t")
		}
		check("comment and blank lines inserted", strings.Join(withComments, "\n"))
		check("tab-separated fields", strings.Join(tabbed, "\n"))

		if !knownDefects() {
			return
		}
		// Oracle 3 (DS1-F4): a PASS needs the deciding line (the first one,
		// as the code reads it) to hold a strict decimal integer inside the
		// rule's compliant range.
		for i, r := range loginDefsRules {
			if r.lo == 0 && r.hi == 0 || base[i] != models.CISPass {
				continue
			}
			for _, l := range lines {
				fs := strings.Fields(strings.TrimSpace(l))
				if len(fs) == 0 || strings.HasPrefix(fs[0], "#") || fs[0] != r.field {
					continue
				}
				v, err := strconv.Atoi(fs[min(1, len(fs)-1)])
				if len(fs) < 2 || err != nil || v < r.lo || v > r.hi {
					t.Fatalf("rule %s PASSES on %s value %q, outside the compliant range [%d,%d] or not an integer (shadow-utils ignores a malformed value and applies a non-compliant default; a negative PASS_MAX_DAYS disables expiry); input %q",
						r.id, r.field, strings.Join(fs[1:], " "), r.lo, r.hi, defs)
				}
				break
			}
		}

		weak := "\nPASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\nPASS_WARN_AGE 0\nENCRYPT_METHOD MD5\n"
		got := loginDefsVerdicts(t, path, defs+weak)
		for i, st := range got {
			if st == models.CISPass {
				t.Fatalf("rule %s PASSES although the last %s line, the one shadow-utils applies, is non-compliant (DS1-F3, first-match vs last-wins); input %q",
					loginDefsRules[i].id, loginDefsRules[i].field, defs+weak)
			}
		}
	})
}

// TestCISKnownFalsePass pins the false PASS verdicts behind DS1-F2/F3/F4.
// Every case was checked against the real component on 2026-11-14:
// shadow-utils 4.17.4 (Debian stable, useradd then /etc/shadow) for
// login.defs, and a privileged Debian container for the overmount (both
// entries listed in /proc/mounts, a binary on the "noexec" path executed).
// Skipped unless DSD_KNOWN_DEFECTS=1; a fix turns it green.
//
// What it does NOT verify: other rules with the same first-match shape
// (sshd_config, useradd defaults), or the remediation text.
func TestCISKnownFalsePass(t *testing.T) {
	if !knownDefects() {
		t.Skip("DS1-F2/F3/F4 known false PASS; set DSD_KNOWN_DEFECTS=1 to run")
	}
	dir := t.TempDir()
	origDefs, origMounts := loginDefsPath, procMountsPath
	t.Cleanup(func() { loginDefsPath, procMountsPath = origDefs, origMounts })
	loginDefsPath = filepath.Join(dir, "login.defs")
	procMountsPath = filepath.Join(dir, "mounts")

	defs := []struct{ name, content, rule, shadowSays string }{
		{"F3 duplicate key, last wins", "PASS_MAX_DAYS 60\nPASS_MAX_DAYS 99999\n", "V-238380", "max=99999"},
		{"F3 duplicate key, last wins", "PASS_MIN_DAYS 1\nPASS_MIN_DAYS 0\n", "5.4.4", "min=0"},
		{"F3 duplicate key, last wins", "PASS_WARN_AGE 7\nPASS_WARN_AGE 2\n", "5.4.6", "warn=2"},
		{"F4 trailing garbage rejected", "PASS_MAX_DAYS 60x\n", "V-238380", "max unset (configuration error)"},
		{"F4 trailing garbage rejected", "PASS_MIN_DAYS 1A0\n", "5.4.4", "min unset (configuration error)"},
		{"F4 trailing garbage rejected", "PASS_WARN_AGE 7days\n", "5.4.6", "warn unset (configuration error)"},
		{"F4 negative max disables expiry", "PASS_MAX_DAYS -1\n", "5.4.1", "max unset (no expiry)"},
	}
	for _, c := range defs {
		t.Run(c.name+"/"+c.rule, func(t *testing.T) {
			if err := os.WriteFile(loginDefsPath, []byte(c.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := ruleByID(c.rule).Check(models.SecurityInfo{}, models.KernelSecurityInfo{}); got.Status == models.CISPass {
				t.Errorf("rule %s PASSES on %q; shadow-utils applies %s", c.rule, c.content, c.shadowSays)
			}
		})
	}

	t.Run("F2 overmount hides noexec", func(t *testing.T) {
		mounts := "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0\ntmpfs /tmp tmpfs rw,relatime 0 0\n"
		if err := os.WriteFile(procMountsPath, []byte(mounts), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"1.1.3", "1.1.4", "1.1.5"} {
			if got := ruleByID(id).Check(models.SecurityInfo{}, models.KernelSecurityInfo{}); got.Status == models.CISPass {
				t.Errorf("rule %s PASSES; the visible /tmp mount (last entry) is rw,relatime", id)
			}
		}
	})
}
