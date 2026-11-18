package tui

// TU1 target A (companion) — the dsd-owned bubbletea model logic is memory-safe
// under a hostile key stream and any option set.
//
// Reachability note (see the TU1 report): bubbletea's key-SEQUENCE PARSER (raw
// stdin bytes -> tea.KeyMsg) is SDK-internal and reads a live fd, so it is not a
// dsd-held buffer a fuzzer can feed — exactly the pro-bing situation. The only
// dsd code in the key path is SingleSelectModel/MultiSelectModel.Update (and
// View). Those switch on msg.String() and index options[cursor]; the one memory-
// safety hazard the code itself flags is an EMPTY options slice (options[0]
// panics) combined with a confirm key. In production today both call sites pass
// hardcoded non-empty lists, but the models are exported and the code comments
// anticipate a future caller building the list dynamically — so this target
// drives them with an arbitrary option count (including zero) and an arbitrary
// key stream, asserting no panic, the cursor never leaves [0,len), and View()
// never panics. It is NOT a terminal-ESC oracle (the styled FRAME is covered by
// render.FuzzTUIStyledFrameNoHostEscape); View output here is the raw interactive
// TUI, which legitimately echoes option bytes.

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// keyFromByte maps one fuzz byte to a key message, covering every branch the
// models switch on plus arbitrary rune keys.
func keyFromByte(b byte) tea.KeyMsg {
	switch b % 9 {
	case 0:
		return tea.KeyMsg{Type: tea.KeyUp}
	case 1:
		return tea.KeyMsg{Type: tea.KeyDown}
	case 2:
		return tea.KeyMsg{Type: tea.KeyEnter}
	case 3:
		return tea.KeyMsg{Type: tea.KeySpace}
	case 4:
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	case 5:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")}
	case 6:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")}
	case 7:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{rune(b)}}
	}
}

func FuzzTUISelectModelKeyStream(f *testing.F) {
	f.Add(uint8(3), "\x00\x01\x02\x03\x04")
	f.Add(uint8(0), "\x02\x03") // empty options + confirm/toggle — the flagged hazard
	f.Add(uint8(1), "\x01\x01\x01\x02")
	f.Add(uint8(5), "\x00\x00\x00\x06\x06\x06\x02")

	f.Fuzz(func(t *testing.T, nOpts uint8, keys string) {
		// Bound the option count so the fixture stays cheap; include 0.
		k := int(nOpts % 12)
		options := make([]string, k)
		for i := range options {
			// Option labels carry fuzz-derived bytes (a dynamic caller could build
			// them from host data); the models must index them safely regardless.
			options[i] = keys + string(rune('A'+i))
		}

		single := tea.Model(SingleSelectModel{title: keys, options: options})
		multi := tea.Model(MultiSelectModel{title: keys, options: options, selected: make([]bool, k)})

		for i := 0; i < len(keys); i++ {
			msg := keyFromByte(keys[i])

			single, _ = single.Update(msg)
			_ = single.View()
			if sm, ok := single.(SingleSelectModel); ok {
				if sm.cursor < 0 || (k > 0 && sm.cursor >= k) {
					t.Fatalf("single cursor out of bounds: cursor=%d len=%d", sm.cursor, k)
				}
			}

			multi, _ = multi.Update(msg)
			_ = multi.View()
			if mm, ok := multi.(MultiSelectModel); ok {
				if mm.cursor < 0 || (k > 0 && mm.cursor >= k) {
					t.Fatalf("multi cursor out of bounds: cursor=%d len=%d", mm.cursor, k)
				}
			}
		}
	})
}
