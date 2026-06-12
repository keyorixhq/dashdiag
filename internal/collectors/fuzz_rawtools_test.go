package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// FuzzParseVGs / FuzzParseLVs / FuzzParseLVMFloat fuzz the LVM tool-output
// parsers (vgs/lvs/pvs). These consume external-tool stdout (THREAT_MODEL_CLI.md
// §5 / SECURITY_SDL.md Layer 2). Invariant: never panic on arbitrary output —
// the false-OK bug class for the LVM collector is "garbled vgs output silently
// yields an empty/clean result", which these guard against regression by
// exercising malformed field counts, weird unit suffixes, and negative sizes.
func FuzzParseVGs(f *testing.F) {
	seeds := []string{
		"vg0 100.00 40.00 wz--n-",
		"vg0 0 0 wz--n-",
		"   ",
		"onlyonefield",
		"two fields",
		"vg <100.00 <40.00", // LVM '<' approximate prefix
		"vg -5 -5",
		"vg abc def",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, out string) {
		_ = parseVGs(out)
	})
}

func FuzzParseLVs(f *testing.F) {
	seeds := []string{
		"pool0 vg0 twi-aotz-- 50.00 10.00  100.00",
		"snap0 vg0 swi-a-s--- 5.00  2.00 origin 10.00",
		"lv vg",
		"",
		"a b c d e f g h i j",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, out string) {
		_, _ = parseLVs(out)
	})
}

func FuzzParseLVMFloat(f *testing.F) {
	for _, s := range []string{"100.00", "<40.5", "", "abc", "-1", "1e308", "NaN", "  12  "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = parseLVMFloat(s)
	})
}

// FuzzParseSteamOSChannel fuzzes the SteamOS channel parser — the rauc-glyph
// file content that previously produced parsing surprises (BUG history). Input
// is file content under /etc; invariant: never panic, label is a substring of
// the raw value or empty.
func FuzzParseSteamOSChannel(f *testing.F) {
	seeds := []string{
		"stable",
		"rel\xef\xbf\xbdbeta", // replacement-char glyph
		"",
		"\x00\x00",
		"beta\nmainline\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		_, _ = parseSteamOSChannel(content)
	})
}

// FuzzApplyRAUCJSON fuzzes the `rauc status --output-format=json` parser that
// backs the SteamOS A/B-slot health check. Input is external-tool stdout
// (THREAT_MODEL_CLI.md §5 raw-tool parsers). Invariant: never panic on
// arbitrary/garbled JSON, and a shape it can't understand must return false so
// the caller falls back to text parsing (rather than a false-OK empty-but-true).
func FuzzApplyRAUCJSON(f *testing.F) {
	seeds := []string{
		`{"slots":[{"rootfs.0":{"state":"booted","boot_status":"good","bootname":"A"}},{"rootfs.1":{"state":"inactive","boot_status":"good","bootname":"B"}}]}`,
		`{"slots":[]}`,
		`{"slots":[{"rootfs.0":{}}]}`, // slot with no bootname
		`{"slots":[{}]}`,              // empty slot object
		`{"slots":null}`,
		`{"slots":"notanarray"}`,
		`not json at all`,
		``,
		`{"slots":[{"rootfs.0":{"state":"booted","bootname":""}}]}`, // empty bootname
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, out string) {
		var info models.SteamOSInfo
		ok := applyRAUCJSON(out, &info)
		// Invariant: a true result must have populated at least one slot name —
		// the false-OK guard (never claim success while reporting nothing).
		if ok && info.RAUCBootedSlot == "" && info.RAUCInactiveSlot == "" {
			t.Fatalf("applyRAUCJSON returned true but found no slot name: %q", out)
		}
	})
}

// FuzzApplyRAUCText fuzzes the plain-text `rauc status` parser (the fallback
// when JSON isn't available). This is the one with a real history: rauc 1.13
// emits Unicode status glyphs (○/⏺) and ANSI color even over a pipe, which an
// earlier ASCII-marker assumption mis-parsed. Invariant: never panic on
// arbitrary text (ANSI escapes, partial glyphs, truncated blocks).
func FuzzApplyRAUCText(f *testing.F) {
	seeds := []string{
		"⏺ [rootfs.0] (/dev/sda2, ext4, booted)\n    bootname: A\n    boot status: good\n○ [rootfs.1] (/dev/sda3, ext4, inactive)\n    bootname: B\n    boot status: good\n",
		"\x1b[34m⏺\x1b[0m [rootfs.0] (/dev/sda2, ext4, booted)\n    bootname: A\n", // ANSI-wrapped
		"bootname: A\n",         // field before any header
		"=== Slot States ===\n", // section header, not a slot
		"[rootfs.0] (",          // truncated header
		"",
		"\x00\x00] (",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, out string) {
		var info models.SteamOSInfo
		applyRAUCText(out, &info)
	})
}
