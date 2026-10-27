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

	results := unreadableDirResults(unreadable)
	if len(results) != 1 || results[0].Level != tlsLvlERR || !strings.Contains(results[0].Err, "could not read /etc/letsencrypt/live") {
		t.Fatalf("results = %+v, want one ERR 'could not read /etc/letsencrypt/live'", results)
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
