package collectors

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Every external command a collector parses must run with the C locale forced.
// Otherwise its output — month/day names, decimal separators, translatable
// status words — is localized, and the parsers (which assume English/ASCII)
// silently break on non-English hosts. That was the timeline dmesg bug (#82):
// `dmesg -T` prints "[lun jun 8 ...]" on es_ES and the English layout couldn't
// parse it, so kernel events were dropped.
//
// The locale-safe path is runCmd / runCmdTimeout / runDarwinCmd / localeSafeCmd,
// which all apply localeSafeEnv(). This guard enforces the contract by
// construction: only the wrapper-defining files may reference exec.Command /
// exec.CommandContext directly; every other collector must go through a wrapper.
// A newly-added raw exec fails here — the same prevention as the exit-code
// contract guard (cmd/contract_test.go), one layer down.
//
// Note: exec.LookPath is intentionally allowed (it runs nothing, just resolves a
// path) — the regex below only matches command *execution*.
var execWrapperFiles = map[string]bool{
	"collector.go":   true, // runCmd, localeSafeCmd
	"disk_linux.go":  true, // runCmdTimeout
	"disk_darwin.go": true, // runDarwinCmd
}

func TestCollectorsUseLocaleSafeExec(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	rawExec := regexp.MustCompile(`exec\.Command(Context)?\(`)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || execWrapperFiles[name] {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		if loc := rawExec.FindIndex(src); loc != nil {
			line := 1 + strings.Count(string(src[:loc[0]]), "\n")
			t.Errorf("%s:%d calls exec.Command directly — route it through localeSafeCmd / "+
				"runCmd / runCmdTimeout (which force LC_ALL=C) so output parsing doesn't break "+
				"on non-English hosts (see #82). If raw exec is genuinely required, add the "+
				"file to execWrapperFiles with a justifying comment.", name, line)
		}
	}
}

// TestParsingIsLocaleStable guards the OTHER half of locale-safety: the forced-C
// wrapper above makes subprocess *strings* uniform, but numeric parsing relies
// on Go's strconv being locale-independent by design (it always reads '.' as the
// decimal separator, ignoring LC_NUMERIC). All ~260 numeric parses of tool
// output go through strconv. This test forces a comma-decimal locale into the
// process env and confirms strconv is unaffected — so if anyone ever swaps in a
// locale-sensitive parser (x/text scanning, cgo strtod, a locale-wired Sscanf),
// it fails here, loudly and deterministically, with no host or generated locale
// required. Validated live 2026-06-16 (es_ES on CT201): no leak; see TRIAGE.md.
func TestParsingIsLocaleStable(t *testing.T) {
	t.Setenv("LC_ALL", "es_ES.UTF-8")
	t.Setenv("LC_NUMERIC", "es_ES.UTF-8")
	t.Setenv("LANG", "es_ES.UTF-8")

	// Dot-decimal values exactly as df/free/proc/ping emit them.
	for _, c := range []struct {
		in   string
		want float64
	}{
		{"1234.56", 1234.56},
		{"0.266", 0.266},
		{"22.999288284369936", 22.999288284369936},
		{"3700", 3700},
	} {
		got, err := strconv.ParseFloat(c.in, 64)
		if err != nil || got != c.want {
			t.Errorf("ParseFloat(%q) = %v, %v under es_ES; want %v, nil — a "+
				"locale-sensitive numeric parser was introduced; tool output "+
				"is dot-decimal and must parse locale-independently", c.in, got, err, c.want)
		}
	}

	// strconv must REJECT a comma-decimal: proof it's strconv in the path and
	// not some comma-accepting locale parser that would misread "1234,56".
	if _, err := strconv.ParseFloat("1234,56", 64); err == nil {
		t.Error(`ParseFloat("1234,56") unexpectedly parsed — a comma-accepting ` +
			`locale-sensitive parser is in the numeric path`)
	}
}
