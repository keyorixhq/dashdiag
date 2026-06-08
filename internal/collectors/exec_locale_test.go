package collectors

import (
	"os"
	"regexp"
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
