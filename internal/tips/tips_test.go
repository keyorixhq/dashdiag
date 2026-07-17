package tips

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/output"
)

// captureStdout redirects os.Stdout for the duration of fn and returns what was
// written. MaybePrintTip/PrintAllTips write directly to os.Stdout, so this is
// the only way to observe their output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = wr
	fn()
	_ = wr.Close()
	os.Stdout = old
	data, _ := io.ReadAll(rd)
	_ = rd.Close()
	return string(data)
}

// withPlainMode forces isPlainMode() to return the given value for the
// duration of fn, then restores the original seam.
func withPlainMode(t *testing.T, plain bool, fn func()) {
	t.Helper()
	old := isPlainMode
	isPlainMode = func() bool { return plain }
	defer func() { isPlainMode = old }()
	fn()
}

func TestPrintAllTips(t *testing.T) {
	// No t.Parallel(): captureStdout swaps the shared os.Stdout global.
	out := captureStdout(t, PrintAllTips)

	if !strings.Contains(out, "DashDiag Tips") {
		t.Errorf("expected header, got: %s", out)
	}
	for _, tip := range tips {
		if !strings.Contains(out, tip.Message) {
			t.Errorf("expected message %q in output", tip.Message)
		}
		if !strings.Contains(out, tip.Command) {
			t.Errorf("expected command %q in output", tip.Command)
		}
	}
	if !strings.Contains(out, "Team") {
		t.Error("expected tiered tip to show its tier label")
	}
}

func TestMaybePrintTip_Disabled(t *testing.T) {
	// No t.Parallel(): withPlainMode mutates the shared isPlainMode package var.
	withPlainMode(t, false, func() {
		s := &State{TipsEnabled: false}
		out := captureStdout(t, func() { MaybePrintTip(s, output.ModeHuman) })
		if out != "" {
			t.Errorf("expected no output when tips disabled, got: %s", out)
		}
		if s.LastTipDate != "" {
			t.Error("state must not change when tips disabled")
		}
	})
}

func TestMaybePrintTip_NonHumanMode(t *testing.T) {
	// No t.Parallel(): withPlainMode mutates the shared isPlainMode package var.
	withPlainMode(t, false, func() {
		s := &State{TipsEnabled: true}
		out := captureStdout(t, func() { MaybePrintTip(s, output.ModeJSON) })
		if out != "" {
			t.Errorf("expected no output in non-human mode, got: %s", out)
		}
	})
}

func TestMaybePrintTip_PlainMode(t *testing.T) {
	// No t.Parallel(): withPlainMode mutates the shared isPlainMode package var.
	withPlainMode(t, true, func() {
		s := &State{TipsEnabled: true}
		out := captureStdout(t, func() { MaybePrintTip(s, output.ModeHuman) })
		if out != "" {
			t.Errorf("expected no output in plain/non-tty mode, got: %s", out)
		}
	})
}

func TestMaybePrintTip_AlreadyShownToday(t *testing.T) {
	// No t.Parallel(): withPlainMode mutates the shared isPlainMode package var.
	withPlainMode(t, false, func() {
		today := time.Now().Format("2006-01-02")
		s := &State{TipsEnabled: true, LastTipDate: today, TipIndex: 3}
		out := captureStdout(t, func() { MaybePrintTip(s, output.ModeHuman) })
		if out != "" {
			t.Errorf("expected no output when already shown today, got: %s", out)
		}
		if s.TipIndex != 3 {
			t.Errorf("expected TipIndex unchanged, got %d", s.TipIndex)
		}
	})
}

func TestMaybePrintTip_PrintsAndAdvances(t *testing.T) {
	// No t.Parallel(): withPlainMode mutates the shared isPlainMode package var.
	withPlainMode(t, false, func() {
		s := &State{TipsEnabled: true, TipIndex: 0}
		out := captureStdout(t, func() { MaybePrintTip(s, output.ModeHuman) })

		if !strings.Contains(out, tips[0].Message) {
			t.Errorf("expected tip message in output, got: %s", out)
		}
		if !strings.Contains(out, tips[0].Command) {
			t.Errorf("expected tip command in output, got: %s", out)
		}
		if !strings.Contains(out, "Tip 1 of") {
			t.Errorf("expected tip counter in output, got: %s", out)
		}
		if s.TipIndex != 1 {
			t.Errorf("expected TipIndex advanced to 1, got %d", s.TipIndex)
		}
		if s.LastTipDate == "" {
			t.Error("expected LastTipDate to be set")
		}
	})
}

func TestMaybePrintTip_WrapsIndex(t *testing.T) {
	// No t.Parallel(): withPlainMode mutates the shared isPlainMode package var.
	withPlainMode(t, false, func() {
		s := &State{TipsEnabled: true, TipIndex: len(tips) - 1}
		captureStdout(t, func() { MaybePrintTip(s, output.ModeHuman) })
		if s.TipIndex != 0 {
			t.Errorf("expected TipIndex to wrap to 0, got %d", s.TipIndex)
		}
	})
}

func TestMaybePrintTip_ShowsTierLabel(t *testing.T) {
	// No t.Parallel(): withPlainMode mutates the shared isPlainMode package var.
	withPlainMode(t, false, func() {
		idx := -1
		for i, tip := range tips {
			if tip.Tier != "" {
				idx = i
				break
			}
		}
		if idx == -1 {
			t.Fatal("expected at least one tiered tip in fixture data")
		}
		s := &State{TipsEnabled: true, TipIndex: idx}
		out := captureStdout(t, func() { MaybePrintTip(s, output.ModeHuman) })
		if !strings.Contains(out, tips[idx].Tier) {
			t.Errorf("expected tier label %q in output, got: %s", tips[idx].Tier, out)
		}
	})
}

func TestMaybePrintTip_RealIsPlainMode(t *testing.T) {
	// No t.Parallel(): captureStdout swaps the shared os.Stdout global.
	s := &State{TipsEnabled: true, TipIndex: 0}
	out := captureStdout(t, func() { MaybePrintTip(s, output.ModeHuman) })
	_ = out
}
