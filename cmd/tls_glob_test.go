//go:build linux || darwin

package cmd

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// deniedDirSource: every Glob comes back empty (what filepath.Glob returns for
// a directory it may not read) while ReadDir reports permission denied for the
// listed directories.
type deniedDirSource struct {
	source.Source
	denied map[string]bool
}

func (deniedDirSource) Glob(string) ([]string, error) { return nil, nil }
func (d deniedDirSource) ReadDir(dir string) ([]string, error) {
	if d.denied[dir] {
		return nil, fmt.Errorf("open %s: %w", dir, os.ErrPermission)
	}
	return nil, nil
}

// An unreadable cert directory must not read as "no certificates": it is
// reported as "could not read <dir>" and lands in Uncheckable (Unverified) in
// the JSON, with a non-ok status.
func TestDetectCertPaths_UnreadableDirIsReportedNotDropped(t *testing.T) {
	src := deniedDirSource{denied: map[string]bool{"/etc/letsencrypt/live": true}}
	paths, unreadable := detectCertPaths(src, []string{
		"/etc/letsencrypt/live/*/cert.pem",
		"/etc/letsencrypt/live/*/fullchain.pem", // same parent: reported once
		"/etc/nginx/ssl/*.crt",                  // readable, genuinely empty
	})
	if len(paths) != 0 {
		t.Fatalf("paths = %v, want none", paths)
	}
	if len(unreadable) != 1 || unreadable[0] != "/etc/letsencrypt/live" {
		t.Fatalf("unreadable = %v, want exactly [/etc/letsencrypt/live]", unreadable)
	}

	results := unreadableDirResults(unreadable, 0) // root: plain error, sudo cannot help
	if len(results) != 1 || results[0].Level != tlsLvlERR || !strings.Contains(results[0].Err, "could not read /etc/letsencrypt/live") || results[0].NeedsRoot {
		t.Fatalf("results = %+v, want one plain ERR 'could not read /etc/letsencrypt/live'", results)
	}

	ti := buildTLSInfo(results, nil, 30)
	if len(ti.Uncheckable) != 1 || ti.Uncheckable[0].Path != "/etc/letsencrypt/live" {
		t.Fatalf("Uncheckable = %+v, want the unreadable dir", ti.Uncheckable)
	}
	if ti.Status == "ok" {
		t.Errorf("Status = %q: an unreadable scan root must never read as ok", ti.Status)
	}
}

// Positive control: a readable-but-empty root must not manufacture a caveat.
func TestDetectCertPaths_ReadableEmptyDirIsClean(t *testing.T) {
	paths, unreadable := detectCertPaths(deniedDirSource{}, []string{"/etc/nginx/ssl/*.crt"})
	if len(paths) != 0 || len(unreadable) != 0 {
		t.Errorf("got paths=%v unreadable=%v, want both empty", paths, unreadable)
	}
}

// The Debian/Ubuntu default /etc/ssl/private is 0710 root:ssl-cert. For a
// non-root run it is "needs root", Unverified in the JSON; as root the same
// failure stays a plain error.
func TestUnreadableDirResults_NonRootNeedsRoot(t *testing.T) {
	src := deniedDirSource{denied: map[string]bool{"/etc/ssl/private": true}}
	_, unreadable := detectCertPaths(src, []string{"/etc/ssl/private/*.pem"})

	results := unreadableDirResults(unreadable, 1000)
	want := "needs root: could not read /etc/ssl/private (re-run with sudo)"
	if len(results) != 1 || results[0].Err != want || !results[0].NeedsRoot || results[0].Level != tlsLvlERR {
		t.Fatalf("results = %+v, want one ERR %q with NeedsRoot", results, want)
	}
	ti := buildTLSInfo(results, nil, 30)
	// Needs-root only: the entry stays in uncheckable[] (truthful), the skip is
	// worded in status_reason, and the status does not by itself leave "ok".
	if len(ti.Uncheckable) != 1 || !ti.Uncheckable[0].NeedsRoot || ti.Status != "ok" ||
		!strings.Contains(ti.StatusReason, "needs root: 1 check skipped") {
		t.Fatalf("Uncheckable=%+v Status=%q Reason=%q, want a needs_root entry, status ok and the skip line", ti.Uncheckable, ti.Status, ti.StatusReason)
	}
	if n := countTLSNeedsRoot(results); n != 1 {
		t.Errorf("countTLSNeedsRoot = %d, want 1", n)
	}

	asRoot := unreadableDirResults(unreadable, 0)
	if asRoot[0].NeedsRoot || strings.Contains(asRoot[0].Err, "needs root") {
		t.Errorf("as root = %+v, want a plain error", asRoot[0])
	}
	// As root the same failure is a real unverified: status leaves "ok".
	if rti := buildTLSInfo(asRoot, nil, 30); rti.Status != "warning" {
		t.Errorf("as root Status = %q, want warning (a root run that cannot read a dir is not fine)", rti.Status)
	}
	if n := countTLSNeedsRoot(asRoot); n != 0 {
		t.Errorf("as root countTLSNeedsRoot = %d, want 0", n)
	}

	// Any other uncheckable entry still raises the status next to a needs-root one.
	other := certResult{Path: "https://x:443", Level: tlsLvlERR, Err: "dial: timeout"}
	mixed := buildTLSInfo(append(append([]certResult{}, results...), other), nil, 30)
	if mixed.Status != "warning" {
		t.Errorf("mixed Status = %q, want warning: a non-root-only failure must still raise it", mixed.Status)
	}
}
