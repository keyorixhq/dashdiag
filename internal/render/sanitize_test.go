package render

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// TestPrintInsightGroup_SanitizesMessageAndHints guards the terminal-escape-
// injection findings that share this one choke point (e.g.
// internal-collectors-06-02 cron, -08-01 dbus, -18-03 kernel_security,
// -21-02 mte, -21-03 multipath, -25-04 oom, -03-06 ceph, -17-07 kafka,
// -27-04 prometheus). Insight.Message and Hints routinely carry untrusted
// collector-sourced text (process/comm names, journal/audit log lines,
// subprocess output) with no upstream sanitization — printInsightGroup must
// strip control/escape bytes before either reaches the terminal.
func TestPrintInsightGroup_SanitizesMessageAndHints(t *testing.T) {
	const escMsg = "cron job failure: \x1b[31mFAKE CRIT\x1b[0m evil"
	const escHint = "last error: \x1b[8mhidden\x1b[0m"
	ins := []models.Insight{{
		Level:   "CRIT",
		Check:   "Cron",
		Message: escMsg,
		Hints:   []string{escHint},
	}}

	for _, mode := range []output.OutputMode{output.ModeHuman, output.ModePlain} {
		r := NewRenderer(mode)
		out := captureStdout(t, func() { r.printInsightGroup(ins) })
		if strings.ContainsRune(out, 0x1b) {
			t.Errorf("mode=%v: output contains a raw ESC byte — control chars were not stripped:\n%q", mode, out)
		}
		if !strings.Contains(out, "FAKE CRIT") || !strings.Contains(out, "evil") {
			t.Errorf("mode=%v: printable text around the escape sequence must survive sanitization:\n%q", mode, out)
		}
		if !strings.Contains(out, "hidden") {
			t.Errorf("mode=%v: hint text must survive sanitization:\n%q", mode, out)
		}
	}
}

// TestPrintRow_SanitizesInsightMessage guards the same class of finding via
// the OTHER row-rendering path (PrintAll/printRow, used by e.g. `dsd health
// --layered`), which formats Insight.Message through a different function
// (formatStatusLine) than printInsightGroup.
func TestPrintRow_SanitizesInsightMessage(t *testing.T) {
	const escMsg = "root is logged in via SSH \x1b[2Jscreen-clear"
	res := runner.Result{Name: "Sessions", Data: &models.SessionsInfo{}}
	insights := []models.Insight{{Level: "CRIT", Check: "Sessions", Message: escMsg}}

	r := NewRenderer(output.ModePlain)
	out := captureStdout(t, func() { r.printRow(res, insights) })
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("output contains a raw ESC byte — control chars were not stripped:\n%q", out)
	}
	if !strings.Contains(out, "screen-clear") {
		t.Errorf("printable text around the escape sequence must survive sanitization:\n%q", out)
	}
}
