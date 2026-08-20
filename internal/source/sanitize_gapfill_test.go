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
