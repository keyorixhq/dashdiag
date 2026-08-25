package source

// sanitize_gapfill_test.go — closes coverage gaps found by a full coverage
// audit: stat/statfs error-text redaction and glob-match-entry redaction
// were never exercised. TestBundleSanitizeErrTextSecret covers files.errText
// and TestBundleSanitizeDirEntrySecret covers dirs — neither reaches
// sanitizeStatErrs (stats/statfss) or the globs half of sanitizeDirsGlobs.

import (
	"errors"
	"strings"
	"testing"
)

func TestBundleSanitizeStatErrTextSecret(t *testing.T) {
	t.Parallel()
	b := NewBundle()
	b.putStat("/etc/secret.d/creds", FileMeta{}, errors.New("dial failed: password=hunter2secret"))

	rep := b.Sanitize(SanitizeOptions{})
	if rep.TotalRedactions == 0 {
		t.Fatalf("report = %+v, want ≥1 redaction", rep)
	}
	rec, ok := b.getStat("/etc/secret.d/creds")
	if !ok {
		t.Fatal("stat record missing after Sanitize")
	}
	if strings.Contains(rec.errText, "hunter2secret") {
		t.Errorf("secret survived in stat errText: %q", rec.errText)
	}
	if !strings.Contains(rec.errText, "dial failed") {
		t.Errorf("non-secret error context dropped: %q", rec.errText)
	}
}

func TestBundleSanitizeStatfsErrTextSecret(t *testing.T) {
	t.Parallel()
	b := NewBundle()
	b.putStatfs("/mnt/data", StatfsInfo{}, errors.New("dial failed: password=hunter2secret"))

	rep := b.Sanitize(SanitizeOptions{})
	if rep.TotalRedactions == 0 {
		t.Fatalf("report = %+v, want ≥1 redaction", rep)
	}
	rec, ok := b.getStatfs("/mnt/data")
	if !ok {
		t.Fatal("statfs record missing after Sanitize")
	}
	if strings.Contains(rec.errText, "hunter2secret") {
		t.Errorf("secret survived in statfs errText: %q", rec.errText)
	}
}

// TestBundleSanitizeGlobEntrySecret is the globs.json counterpart to
// TestBundleSanitizeDirEntrySecret (which only covers dirs).
func TestBundleSanitizeGlobEntrySecret(t *testing.T) {
	t.Parallel()
	b := NewBundle()
	b.putGlob("/mnt/secrets/*", []string{"readme.txt", "token=abc123secretvalue.txt"})

	rep := b.Sanitize(SanitizeOptions{})
	if rep.TotalRedactions == 0 {
		t.Fatalf("report = %+v, want ≥1 redaction", rep)
	}
	matches, ok := b.getGlob("/mnt/secrets/*")
	if !ok {
		t.Fatal("glob record missing after Sanitize")
	}
	for _, m := range matches {
		if strings.Contains(m, "abc123secretvalue") {
			t.Errorf("secret survived in glob match: %q", m)
		}
	}
}

// TestBundleSanitizeDirEntryNoSecretsUnchanged covers redactSlice's
// "nothing changed" early return (sanitize.go:277-278): a dir listing with
// no secret-shaped entries at all must come back byte-for-byte identical,
// not just "no redactions counted" — TestBundleSanitizeDirEntrySecret only
// ever seeds a list containing at least one match.
func TestBundleSanitizeDirEntryNoSecretsUnchanged(t *testing.T) {
	t.Parallel()
	b := NewBundle()
	b.putDir("/mnt/data", []string{"readme.txt", "notes.md"})

	rep := b.Sanitize(SanitizeOptions{})
	if rep.TotalRedactions != 0 {
		t.Errorf("report = %+v, want 0 redactions for a secret-free dir listing", rep)
	}
	entries, ok := b.getDir("/mnt/data")
	if !ok {
		t.Fatal("dir record missing after Sanitize")
	}
	if len(entries) != 2 || entries[0] != "readme.txt" || entries[1] != "notes.md" {
		t.Errorf("entries = %v, want unchanged [readme.txt notes.md]", entries)
	}
}

// TestBundleSanitizeCmdErrTextSecret is the cmds.json counterpart to
// TestBundleSanitizeStatErrTextSecret/StatfsErrTextSecret above: a
// captured command's failure text (e.g. an exec error echoing back part of
// the invocation, or a diagnostic tool's own error output) can carry a
// secret the same way stat/statfs errText already does — cr.res.Stdout and
// cr.res.Stderr redaction were already covered, but cr.errText was not.
func TestBundleSanitizeCmdErrTextSecret(t *testing.T) {
	t.Parallel()
	b := NewBundle()
	name, args := "probe-tool", []string{"--verbose"}
	b.putCmd(name, args, Result{}, errors.New("dial failed: password=hunter2secret"))

	rep := b.Sanitize(SanitizeOptions{})
	if rep.TotalRedactions == 0 {
		t.Fatalf("report = %+v, want ≥1 redaction", rep)
	}
	rec, ok := b.getCmd(name, args)
	if !ok {
		t.Fatal("cmd record missing after Sanitize")
	}
	if strings.Contains(rec.errText, "hunter2secret") {
		t.Errorf("secret survived in cmd errText: %q", rec.errText)
	}
	if !strings.Contains(rec.errText, "dial failed") {
		t.Errorf("non-secret error context dropped: %q", rec.errText)
	}
}

// TestBundleSanitizeLinkErrTextSecret is the errText counterpart to
// TestBundleSanitizeLinkTarget (sanitize_test.go), which only covers
// rec.target — a readlink error string can embed a path/token the same way
// a resolved target can.
func TestBundleSanitizeLinkErrTextSecret(t *testing.T) {
	t.Parallel()
	b := NewBundle()
	// A generic error (not fs.ErrNotExist/fs.ErrPermission) routes through
	// putLink's default branch, which sets errText.
	b.putLink("/etc/some-link", "", errors.New("readlink /etc/some-link: dial failed: password=hunter2secret"))

	rep := b.Sanitize(SanitizeOptions{})
	if rep.TotalRedactions == 0 {
		t.Fatalf("report = %+v, want ≥1 redaction", rep)
	}
	rec, ok := b.getLink("/etc/some-link")
	if !ok {
		t.Fatal("link record missing after Sanitize")
	}
	if strings.Contains(rec.errText, "hunter2secret") {
		t.Errorf("secret survived in link errText: %q", rec.errText)
	}
	if !strings.Contains(rec.errText, "dial failed") {
		t.Errorf("non-secret error context dropped: %q", rec.errText)
	}
}
