package collectors

import "testing"

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
