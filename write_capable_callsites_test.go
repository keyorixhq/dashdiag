package installscript

// write_capable_callsites_test.go — the structural invariant GAP-1
// (docs/product-claim-gaps-2026-09-02.md) asked for: every write-capable call
// site in non-test code (os.Create, os.WriteFile, os.OpenFile with write
// flags, os.Remove*, os.Rename, os.Mkdir*, os.Chmod, os.Symlink/Link) is
// classified once, here, into "writes the operator's own output artifact" —
// dsd's own state under ~/.dsd, an operator-named --out/--report path, a hook
// file the operator explicitly asked `dsd hook install` to create — versus
// "touches a target": some path the operator did not name and would not
// expect a read-only diagnostic tool to write to. The second set must be
// empty everywhere except internal/fleet, whose whole reason for existing is
// to write ONE thing to a remote target (the uploaded binary) and remove it
// again (internal/fleet/fleet.go's cleanupRemoteBin — see
// TestRunHost_CleansUpOnRemoteCommandFailure and friends in
// internal/fleet/sshexec_test.go for that half of the contract).
//
// This is a CLOSED allowlist, not a semantic classifier: every CURRENT write
// call site's file is listed below with why it's "own artifact". A new write
// call site in a file not on this list, outside internal/fleet, fails the
// build — forcing whoever added it to either move the classification here
// (with a reason) or reconsider whether a read-only diagnostic tool should be
// writing there at all. That failure is the point: it's the same "artifact
// you can hand a security reviewer" shape as scripts/check-nonroot-invariant.sh
// and internal/cis's TestRulesHaveNoHardcodedDistroHints.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// writeCallRe matches the exact function set GAP-1 named. OpenFile is
// included unconditionally here; openFileIsWrite below filters out read-only
// opens (e.g. internal/collectors/logs_linux.go's O_RDONLY /dev/kmsg read)
// before a match counts.
var writeCallRe = regexp.MustCompile(`\bos\.(Create|WriteFile|OpenFile|Remove|RemoveAll|Rename|Mkdir|MkdirAll|Chmod|Symlink|Link)\(`)

// openFileIsWrite reports whether a matched os.OpenFile(...) call requests a
// write-capable flag. A line with only O_RDONLY (or no flag constant at all,
// which shouldn't happen for a real os.OpenFile call) is not a write.
func openFileIsWrite(line string) bool {
	for _, flag := range []string{"O_WRONLY", "O_RDWR", "O_CREATE", "O_APPEND", "O_TRUNC", "O_EXCL"} {
		if strings.Contains(line, flag) {
			return true
		}
	}
	return false
}

// writeCapableAllowlist maps a repo-relative file path to why every
// write-capable call site IN THAT FILE is the operator's own output artifact,
// not a touched target. File-level, not line-level: line numbers drift with
// every edit and would make this test a maintenance trap rather than a guard;
// every file below was read in full when added and confirmed to contain only
// own-artifact writes.
var writeCapableAllowlist = map[string]string{
	"cmd/hook.go": "`dsd hook install` — an explicitly-named, opt-in installer " +
		"command (has its own --dry-run flag) that writes shell/git/CI hook " +
		"files the operator asked for by running it, in their own shell rc or " +
		"their own current repo — not a side effect of a read-only diagnostic command.",
	"cmd/root.go": "os.OpenFile(outPath, ...) — outPath is a user-supplied --out CLI flag by design.",
	"cmd/writefile.go": "writeFileNoFollow — shared helper for a predictable/fixed " +
		"destination path (a hostname-derived report filename, a fixed hook script " +
		"path); every caller passes an operator-named or operator-requested path.",
	"internal/baseline/baseline.go":          "dsd's own baseline/snapshot state under its state dir (atomic temp+rename).",
	"internal/baseline/golden.go":            "dsd's own golden-snapshot state (atomic temp+rename).",
	"internal/baseline/security_baseline.go": "dsd's own security-baseline state (atomic temp+rename).",
	"internal/init/firstrun.go":              "path is ~/.dsd.yaml — dsd's own first-run config file.",
	"internal/render/writefile.go":           "writeReportFileNoFollow — backs --report/--report-html, an operator-requested output path.",
	"internal/selfupdate/nudge.go":           "dsd's own update-nudge state file under its state dir (atomic temp+rename).",
	"internal/selfupdate/selfupdate.go":      "`dsd update` replacing its OWN running binary on the OPERATOR'S OWN machine, gated by signature verification (SECURITY.md) — the self in self-update, not a third-party target.",
	"internal/source/helpers.go":             "bundle-writing helper for `dsd capture`/`dsd sanitize` — path comes from --out or a generated default under the operator's cwd.",
	"internal/source/persist.go":             "bundle persistence for `dsd capture --raw` — same operator-requested output path as helpers.go.",
	"internal/source/tarball.go":             "capture bundle save/extract (`dsd capture`/`dsd replay`) — operator-requested path, plus its own temp-dir extraction area.",
	"internal/store/jsonl.go":                "dsd's own local metrics/state store under its state dir.",
	"internal/store/lock.go":                 "dsd's own store lock file under its state dir.",
	"internal/store/prune.go":                "dsd's own store pruning (temp+rename) under its state dir.",
	"internal/tips/state.go":                 "dsd's own tips-shown state cache under its state dir (atomic temp+rename).",
}

// TestWriteCapableCallSitesAreOwnArtifactsOnly is the invariant: walk every
// tracked, non-test .go file; any write-capable call site must be either
// under internal/fleet/ (the one place dsd deliberately writes to a target —
// see this file's header) or in a file on writeCapableAllowlist above.
func TestWriteCapableCallSitesAreOwnArtifactsOnly(t *testing.T) {
	root := repoRoot(t)
	found := 0
	var unclassified []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if strings.HasPrefix(info.Name(), ".") || info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}

		hasWrite := false
		for line := range strings.SplitSeq(string(data), "\n") {
			m := writeCallRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if m[1] == "OpenFile" && !openFileIsWrite(line) {
				continue
			}
			hasWrite = true
		}
		if !hasWrite {
			return nil
		}
		found++

		if strings.HasPrefix(rel, "internal/fleet/") {
			return nil // the one deliberate target-touching exception — see header
		}
		if _, ok := writeCapableAllowlist[rel]; ok {
			return nil
		}
		unclassified = append(unclassified, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walking module for write-capable call sites: %v", err)
	}

	if found == 0 {
		t.Fatal("found zero write-capable call sites — the scan itself is broken, not the module " +
			"(this repo has dozens: dsd's own state store, --out/--report paths, capture bundles)")
	}
	for _, rel := range unclassified {
		t.Errorf("%s has a write-capable call site (os.Create/WriteFile/OpenFile-with-write-flags/"+
			"Remove*/Rename/Mkdir*/Chmod/Symlink/Link) that is neither under internal/fleet/ nor "+
			"classified in writeCapableAllowlist — read the file, decide whether it's the operator's "+
			"own output artifact or something touching a path they didn't name, then add it to the "+
			"allowlist with a reason (or fix it, if it's the latter)", rel)
	}
}
