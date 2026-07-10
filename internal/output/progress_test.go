package output

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// captureStderr redirects os.Stderr for the duration of fn and returns what
// was written. CommandProgress writes directly to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = wr
	fn()
	_ = wr.Close()
	os.Stderr = old
	data, _ := io.ReadAll(rd)
	_ = rd.Close()
	return string(data)
}

func TestNewCommandProgress(t *testing.T) {
	p := NewCommandProgress("health", 30*time.Second, ModeHuman, 5)
	if p.label != "health" || p.estimate != 30*time.Second || p.mode != ModeHuman || p.total != 5 {
		t.Errorf("unexpected fields: %+v", p)
	}
	if p.done != 0 {
		t.Errorf("expected done=0, got %d", p.done)
	}
}

func TestCommandProgress_Start_Human(t *testing.T) {
	p := NewCommandProgress("health", 30*time.Second, ModeHuman, 5)
	out := captureStderr(t, p.Start)

	if !strings.Contains(out, "health") {
		t.Errorf("expected label in output, got: %s", out)
	}
	if !strings.Contains(out, "under 30s") {
		t.Errorf("expected estimate text, got: %s", out)
	}
	if !strings.Contains(out, "─") {
		t.Errorf("expected separator rule, got: %s", out)
	}
	if p.start.IsZero() {
		t.Error("expected start time to be set")
	}
}

func TestCommandProgress_Start_NonHuman(t *testing.T) {
	p := NewCommandProgress("health", 10*time.Second, ModePlain, 5)
	out := captureStderr(t, p.Start)

	if !strings.Contains(out, "[INFO] health") {
		t.Errorf("expected [INFO] prefix, got: %s", out)
	}
	if strings.Contains(out, "─") {
		t.Errorf("expected no separator rule in non-human mode, got: %s", out)
	}
}

func TestCommandProgress_Step(t *testing.T) {
	p := NewCommandProgress("health", 10*time.Second, ModePlain, 3)
	out := captureStderr(t, func() {
		p.Step("cpu")
		p.Step("disk")
	})
	if !strings.Contains(out, "step 1/3") || !strings.Contains(out, "step 2/3") {
		t.Errorf("expected step progress lines, got: %s", out)
	}
	if p.done != 2 {
		t.Errorf("expected done=2, got %d", p.done)
	}
}

func TestCommandProgress_Step_HumanModeSilent(t *testing.T) {
	p := NewCommandProgress("health", 10*time.Second, ModeHuman, 3)
	out := captureStderr(t, func() { p.Step("cpu") })
	if out != "" {
		t.Errorf("expected no step output in human mode, got: %s", out)
	}
	if p.done != 1 {
		t.Errorf("expected done counter still incremented, got %d", p.done)
	}
}

func TestCommandProgress_Elapsed(t *testing.T) {
	p := NewCommandProgress("health", 10*time.Second, ModeHuman, 3)
	captureStderr(t, p.Start)
	time.Sleep(2 * time.Millisecond)
	if p.Elapsed() <= 0 {
		t.Error("expected positive elapsed duration after Start")
	}
}

func TestCommandProgress_Note_Human(t *testing.T) {
	p := NewCommandProgress("health", 10*time.Second, ModeHuman, 3)
	out := captureStderr(t, func() { p.Note("skipping docker checks") })
	if !strings.Contains(out, "skipping docker checks") {
		t.Errorf("expected note text, got: %s", out)
	}
	if !strings.Contains(out, "ℹ") {
		t.Errorf("expected human-mode info glyph, got: %s", out)
	}
}

func TestCommandProgress_Note_NonHuman(t *testing.T) {
	p := NewCommandProgress("health", 10*time.Second, ModePlain, 3)
	out := captureStderr(t, func() { p.Note("skipping docker checks") })
	if !strings.Contains(out, "[INFO] skipping docker checks") {
		t.Errorf("expected [INFO]-prefixed note, got: %s", out)
	}
}

func TestCommandProgress_Done_NonHuman(t *testing.T) {
	p := NewCommandProgress("health", 10*time.Second, ModePlain, 3)
	captureStderr(t, p.Start)
	out := captureStderr(t, p.Done)
	if !strings.Contains(out, "[INFO] done in") {
		t.Errorf("expected done summary line, got: %s", out)
	}
}

func TestCommandProgress_Done_HumanSilent(t *testing.T) {
	p := NewCommandProgress("health", 10*time.Second, ModeHuman, 3)
	captureStderr(t, p.Start)
	out := captureStderr(t, p.Done)
	if out != "" {
		t.Errorf("expected no done output in human mode, got: %s", out)
	}
}
