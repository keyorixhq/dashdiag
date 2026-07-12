package tui

import (
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// isQuitCmd reports whether cmd is bubbletea's tea.Quit — the model asked
// the program to exit.
func isQuitCmd(t *testing.T, cmd tea.Cmd) bool {
	t.Helper()
	if cmd == nil {
		return false
	}
	_, ok := cmd().(tea.QuitMsg)
	return ok
}

// ── SingleSelectModel.Update ────────────────────────────────────────────────

func TestSingleSelectModel_Update(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		start      SingleSelectModel
		key        string
		wantCursor int
		wantChosen string
		wantDone   bool
		wantQuit   bool
	}{
		{
			name:       "quit via q",
			start:      SingleSelectModel{options: []string{"a", "b", "c"}, cursor: 1},
			key:        "q",
			wantCursor: 1,
			wantDone:   true,
			wantQuit:   true,
		},
		{
			name:       "quit via ctrl+c",
			start:      SingleSelectModel{options: []string{"a", "b", "c"}, cursor: 0},
			key:        "ctrl+c",
			wantCursor: 0,
			wantDone:   true,
			wantQuit:   true,
		},
		{
			name:       "up decrements cursor",
			start:      SingleSelectModel{options: []string{"a", "b", "c"}, cursor: 2},
			key:        "up",
			wantCursor: 1,
		},
		{
			name:       "up via k",
			start:      SingleSelectModel{options: []string{"a", "b", "c"}, cursor: 2},
			key:        "k",
			wantCursor: 1,
		},
		{
			name:       "up at top stays clamped",
			start:      SingleSelectModel{options: []string{"a", "b", "c"}, cursor: 0},
			key:        "up",
			wantCursor: 0,
		},
		{
			name:       "down increments cursor",
			start:      SingleSelectModel{options: []string{"a", "b", "c"}, cursor: 0},
			key:        "down",
			wantCursor: 1,
		},
		{
			name:       "down via j",
			start:      SingleSelectModel{options: []string{"a", "b", "c"}, cursor: 0},
			key:        "j",
			wantCursor: 1,
		},
		{
			name:       "down at bottom stays clamped",
			start:      SingleSelectModel{options: []string{"a", "b", "c"}, cursor: 2},
			key:        "down",
			wantCursor: 2,
		},
		{
			name:       "enter selects option",
			start:      SingleSelectModel{options: []string{"a", "b", "c"}, cursor: 1},
			key:        "enter",
			wantCursor: 1,
			wantChosen: "b",
			wantDone:   true,
			wantQuit:   true,
		},
		{
			name:       "space selects option",
			start:      SingleSelectModel{options: []string{"a", "b", "c"}, cursor: 2},
			key:        " ",
			wantCursor: 2,
			wantChosen: "c",
			wantDone:   true,
			wantQuit:   true,
		},
		{
			name:       "unhandled key is a no-op",
			start:      SingleSelectModel{options: []string{"a", "b", "c"}, cursor: 1},
			key:        "x",
			wantCursor: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var keyMsg tea.KeyMsg
			switch tc.key {
			case "ctrl+c":
				keyMsg = tea.KeyMsg{Type: tea.KeyCtrlC}
			case "up":
				keyMsg = tea.KeyMsg{Type: tea.KeyUp}
			case "down":
				keyMsg = tea.KeyMsg{Type: tea.KeyDown}
			case "enter":
				keyMsg = tea.KeyMsg{Type: tea.KeyEnter}
			case " ":
				keyMsg = tea.KeyMsg{Type: tea.KeySpace}
			default:
				keyMsg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tc.key)}
			}

			got, cmd := tc.start.Update(keyMsg)

			m, ok := got.(SingleSelectModel)
			if !ok {
				t.Fatalf("Update() returned type %T, want SingleSelectModel", got)
			}
			if m.cursor != tc.wantCursor {
				t.Errorf("cursor = %d, want %d", m.cursor, tc.wantCursor)
			}
			if m.chosen != tc.wantChosen {
				t.Errorf("chosen = %q, want %q", m.chosen, tc.wantChosen)
			}
			if m.done != tc.wantDone {
				t.Errorf("done = %v, want %v", m.done, tc.wantDone)
			}
			if isQuitCmd(t, cmd) != tc.wantQuit {
				t.Errorf("isQuitCmd = %v, want %v", isQuitCmd(t, cmd), tc.wantQuit)
			}
		})
	}
}

func TestSingleSelectModel_Init(t *testing.T) {
	t.Parallel()
	m := SingleSelectModel{}
	if cmd := m.Init(); cmd != nil {
		t.Errorf("Init() = %v, want nil", cmd)
	}
}

func TestSingleSelectModel_Update_NonKeyMsg(t *testing.T) {
	t.Parallel()
	m := SingleSelectModel{options: []string{"a", "b"}, cursor: 0}
	got, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	sm, ok := got.(SingleSelectModel)
	if !ok {
		t.Fatalf("Update() returned type %T, want SingleSelectModel", got)
	}
	if sm.cursor != 0 || sm.done {
		t.Errorf("non-key msg mutated model: %+v", sm)
	}
	if cmd != nil {
		t.Errorf("cmd = %v, want nil", cmd)
	}
}

func TestSingleSelectModel_View(t *testing.T) {
	t.Parallel()

	m := SingleSelectModel{title: "Pick one", options: []string{"alpha", "beta", "gamma"}, cursor: 1}
	out := m.View()

	if !strings.Contains(out, "Pick one") {
		t.Errorf("View() missing title, got %q", out)
	}
	for _, opt := range []string{"alpha", "beta", "gamma"} {
		if !strings.Contains(out, opt) {
			t.Errorf("View() missing option %q, got %q", opt, out)
		}
	}
	if !strings.Contains(out, "> beta") {
		t.Errorf("View() missing cursor marker on selected option, got %q", out)
	}
	if !strings.Contains(out, "navigate") {
		t.Errorf("View() missing footer help text, got %q", out)
	}
}

// ── MultiSelectModel.Update ─────────────────────────────────────────────────

func TestMultiSelectModel_Update(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		start        MultiSelectModel
		key          tea.KeyMsg
		wantCursor   int
		wantSelected []bool
		wantDone     bool
		wantQuit     bool
	}{
		{
			name:         "quit via q",
			start:        MultiSelectModel{options: []string{"a", "b"}, selected: []bool{false, false}, cursor: 0},
			key:          tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")},
			wantCursor:   0,
			wantSelected: []bool{false, false},
			wantDone:     true,
			wantQuit:     true,
		},
		{
			name:         "quit via ctrl+c",
			start:        MultiSelectModel{options: []string{"a", "b"}, selected: []bool{false, false}, cursor: 0},
			key:          tea.KeyMsg{Type: tea.KeyCtrlC},
			wantCursor:   0,
			wantSelected: []bool{false, false},
			wantDone:     true,
			wantQuit:     true,
		},
		{
			name:         "up decrements cursor",
			start:        MultiSelectModel{options: []string{"a", "b", "c"}, selected: []bool{false, false, false}, cursor: 2},
			key:          tea.KeyMsg{Type: tea.KeyUp},
			wantCursor:   1,
			wantSelected: []bool{false, false, false},
		},
		{
			name:         "up via k stays clamped at top",
			start:        MultiSelectModel{options: []string{"a", "b"}, selected: []bool{false, false}, cursor: 0},
			key:          tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")},
			wantCursor:   0,
			wantSelected: []bool{false, false},
		},
		{
			name:         "down increments cursor",
			start:        MultiSelectModel{options: []string{"a", "b", "c"}, selected: []bool{false, false, false}, cursor: 0},
			key:          tea.KeyMsg{Type: tea.KeyDown},
			wantCursor:   1,
			wantSelected: []bool{false, false, false},
		},
		{
			name:         "down via j stays clamped at bottom",
			start:        MultiSelectModel{options: []string{"a", "b"}, selected: []bool{false, false}, cursor: 1},
			key:          tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")},
			wantCursor:   1,
			wantSelected: []bool{false, false},
		},
		{
			name:         "space toggles selection on",
			start:        MultiSelectModel{options: []string{"a", "b"}, selected: []bool{false, false}, cursor: 1},
			key:          tea.KeyMsg{Type: tea.KeySpace},
			wantCursor:   1,
			wantSelected: []bool{false, true},
		},
		{
			name:         "space toggles selection off",
			start:        MultiSelectModel{options: []string{"a", "b"}, selected: []bool{false, true}, cursor: 1},
			key:          tea.KeyMsg{Type: tea.KeySpace},
			wantCursor:   1,
			wantSelected: []bool{false, false},
		},
		{
			name:         "enter confirms",
			start:        MultiSelectModel{options: []string{"a", "b"}, selected: []bool{true, false}, cursor: 0},
			key:          tea.KeyMsg{Type: tea.KeyEnter},
			wantCursor:   0,
			wantSelected: []bool{true, false},
			wantDone:     true,
			wantQuit:     true,
		},
		{
			name:         "unhandled key is a no-op",
			start:        MultiSelectModel{options: []string{"a", "b"}, selected: []bool{false, false}, cursor: 0},
			key:          tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")},
			wantCursor:   0,
			wantSelected: []bool{false, false},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, cmd := tc.start.Update(tc.key)
			m, ok := got.(MultiSelectModel)
			if !ok {
				t.Fatalf("Update() returned type %T, want MultiSelectModel", got)
			}
			if m.cursor != tc.wantCursor {
				t.Errorf("cursor = %d, want %d", m.cursor, tc.wantCursor)
			}
			if len(m.selected) != len(tc.wantSelected) {
				t.Fatalf("selected len = %d, want %d", len(m.selected), len(tc.wantSelected))
			}
			for i := range m.selected {
				if m.selected[i] != tc.wantSelected[i] {
					t.Errorf("selected[%d] = %v, want %v", i, m.selected[i], tc.wantSelected[i])
				}
			}
			if m.done != tc.wantDone {
				t.Errorf("done = %v, want %v", m.done, tc.wantDone)
			}
			if isQuitCmd(t, cmd) != tc.wantQuit {
				t.Errorf("isQuitCmd = %v, want %v", isQuitCmd(t, cmd), tc.wantQuit)
			}
		})
	}
}

func TestMultiSelectModel_Init(t *testing.T) {
	t.Parallel()
	m := MultiSelectModel{}
	if cmd := m.Init(); cmd != nil {
		t.Errorf("Init() = %v, want nil", cmd)
	}
}

func TestMultiSelectModel_Update_NonKeyMsg(t *testing.T) {
	t.Parallel()
	m := MultiSelectModel{options: []string{"a", "b"}, selected: []bool{false, false}, cursor: 0}
	got, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	sm, ok := got.(MultiSelectModel)
	if !ok {
		t.Fatalf("Update() returned type %T, want MultiSelectModel", got)
	}
	if sm.cursor != 0 || sm.done || sm.selected[0] || sm.selected[1] {
		t.Errorf("non-key msg mutated model: %+v", sm)
	}
	if cmd != nil {
		t.Errorf("cmd = %v, want nil", cmd)
	}
}

func TestMultiSelectModel_View(t *testing.T) {
	t.Parallel()

	m := MultiSelectModel{
		title:    "Pick some",
		options:  []string{"alpha", "beta"},
		selected: []bool{true, false},
		cursor:   0,
	}
	out := m.View()

	if !strings.Contains(out, "Pick some") {
		t.Errorf("View() missing title, got %q", out)
	}
	if !strings.Contains(out, "> [x] alpha") {
		t.Errorf("View() missing cursor+checked marker for alpha, got %q", out)
	}
	if !strings.Contains(out, "  [ ] beta") {
		t.Errorf("View() missing unchecked marker for beta, got %q", out)
	}
	if !strings.Contains(out, "toggle") {
		t.Errorf("View() missing footer help text, got %q", out)
	}
}

// ── RunSingleSelect / RunMultiSelect (text fallback, since the test process
// is never a TTY) ────────────────────────────────────────────────────────

func withStdin(t *testing.T, content string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = old
	})
	go func() {
		_, _ = w.WriteString(content)
		_ = w.Close()
	}()
}

func TestRunSingleSelect_TextFallback(t *testing.T) {
	// Mutates os.Stdin — cannot run in parallel with siblings in this file.
	withStdin(t, "2\n")

	got, err := RunSingleSelect("Choose", []string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("RunSingleSelect: %v", err)
	}
	if got != "b" {
		t.Errorf("RunSingleSelect() = %q, want %q", got, "b")
	}
}

func TestRunSingleSelect_TextFallback_InvalidNumber(t *testing.T) {
	withStdin(t, "99\n")

	got, err := RunSingleSelect("Choose", []string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("RunSingleSelect: %v", err)
	}
	if got != "" {
		t.Errorf("RunSingleSelect() = %q, want empty string for out-of-range input", got)
	}
}

func TestRunSingleSelect_TextFallback_NonNumeric(t *testing.T) {
	withStdin(t, "not-a-number\n")

	got, err := RunSingleSelect("Choose", []string{"a", "b"})
	if err != nil {
		t.Fatalf("RunSingleSelect: %v", err)
	}
	if got != "" {
		t.Errorf("RunSingleSelect() = %q, want empty string for non-numeric input", got)
	}
}

func TestRunSingleSelect_TextFallback_EmptyStdin(t *testing.T) {
	withStdin(t, "")

	got, err := RunSingleSelect("Choose", []string{"a", "b"})
	if err != nil {
		t.Fatalf("RunSingleSelect: %v", err)
	}
	if got != "" {
		t.Errorf("RunSingleSelect() = %q, want empty string when stdin has no line", got)
	}
}

func TestRunMultiSelect_TextFallback(t *testing.T) {
	withStdin(t, "1,3\n")

	got, err := RunMultiSelect("Choose some", []string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("RunMultiSelect: %v", err)
	}
	want := []string{"a", "c"}
	if len(got) != len(want) {
		t.Fatalf("RunMultiSelect() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("RunMultiSelect()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRunMultiSelect_TextFallback_MixedValidInvalid(t *testing.T) {
	withStdin(t, "1, 99, abc, 2\n")

	got, err := RunMultiSelect("Choose some", []string{"a", "b"})
	if err != nil {
		t.Fatalf("RunMultiSelect: %v", err)
	}
	want := []string{"a", "b"}
	if len(got) != len(want) {
		t.Fatalf("RunMultiSelect() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("RunMultiSelect()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRunMultiSelect_TextFallback_EmptyStdin(t *testing.T) {
	withStdin(t, "")

	got, err := RunMultiSelect("Choose some", []string{"a", "b"})
	if err != nil {
		t.Fatalf("RunMultiSelect: %v", err)
	}
	if got != nil {
		t.Errorf("RunMultiSelect() = %v, want nil when stdin has no line", got)
	}
}

func TestRunMultiSelect_TextFallback_NoneValid(t *testing.T) {
	withStdin(t, "99,abc\n")

	got, err := RunMultiSelect("Choose some", []string{"a", "b"})
	if err != nil {
		t.Fatalf("RunMultiSelect: %v", err)
	}
	if got != nil {
		t.Errorf("RunMultiSelect() = %v, want nil when nothing valid was selected", got)
	}
}
