package tui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// checkTTY and teaRun are overridable in tests to cover the TTY dispatch path
// without a real terminal.
var (
	checkTTY = IsTTY
	teaRun   = func(p *tea.Program) (tea.Model, error) { return p.Run() }
)

// ── Single select ─────────────────────────────────────────────────────────────

type SingleSelectModel struct {
	title   string
	options []string
	cursor  int
	chosen  string
	done    bool
}

func (m SingleSelectModel) Init() tea.Cmd { return nil }

func (m SingleSelectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.done = true
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.options)-1 {
				m.cursor++
			}
		case "enter", " ":
			m.chosen = m.options[m.cursor]
			m.done = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m SingleSelectModel) View() string {
	var s strings.Builder
	s.WriteString(m.title + "\n\n")
	for i, opt := range m.options {
		cursor := "  "
		if m.cursor == i {
			cursor = "> "
		}
		s.WriteString(cursor + opt + "\n")
	}
	s.WriteString("\n↑/↓ navigate  enter select  q quit\n")
	return s.String()
}

func RunSingleSelect(title string, options []string) (string, error) {
	if !checkTTY() {
		return singleSelectText(title, options)
	}
	m := SingleSelectModel{title: title, options: options}
	p := tea.NewProgram(m)
	result, err := teaRun(p)
	if err != nil {
		return "", err
	}
	selected, ok := result.(SingleSelectModel)
	if !ok {
		return "", fmt.Errorf("unexpected model type from teaRun: %T", result)
	}
	return selected.chosen, nil
}

func singleSelectText(title string, options []string) (string, error) {
	fmt.Println(title)
	for i, opt := range options {
		fmt.Printf("%d) %s\n", i+1, opt)
	}
	fmt.Printf("Enter number (1-%d): ", len(options))
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return "", nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
	if err != nil || n < 1 || n > len(options) {
		return "", nil
	}
	return options[n-1], nil
}

// ── Multi select ──────────────────────────────────────────────────────────────

type MultiSelectModel struct {
	title    string
	options  []string
	selected []bool
	cursor   int
	done     bool
}

func (m MultiSelectModel) Init() tea.Cmd { return nil }

func (m MultiSelectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.done = true
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.options)-1 {
				m.cursor++
			}
		case " ":
			m.selected[m.cursor] = !m.selected[m.cursor]
		case "enter":
			m.done = true // NOSONAR — same body as ctrl+c/q: both quit; confirm and cancel both terminate the selector
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m MultiSelectModel) View() string {
	var s strings.Builder
	s.WriteString(m.title + "\n\n")
	for i, opt := range m.options {
		cursor := "  "
		if m.cursor == i {
			cursor = "> "
		}
		checked := "[ ]"
		if m.selected[i] {
			checked = "[x]"
		}
		s.WriteString(cursor + checked + " " + opt + "\n")
	}
	s.WriteString("\n↑/↓ navigate  space toggle  enter confirm  q quit\n")
	return s.String()
}

func RunMultiSelect(title string, options []string) ([]string, error) {
	if !checkTTY() {
		return multiSelectText(title, options)
	}
	m := MultiSelectModel{
		title:    title,
		options:  options,
		selected: make([]bool, len(options)),
	}
	p := tea.NewProgram(m)
	result, err := teaRun(p)
	if err != nil {
		return nil, err
	}
	final, ok := result.(MultiSelectModel)
	if !ok {
		return nil, fmt.Errorf("unexpected model type from teaRun: %T", result)
	}
	var chosen []string
	for i, sel := range final.selected {
		if sel {
			chosen = append(chosen, options[i]) //nolint:gosec // G602 false-positive: selected is always init with make([]bool, len(options))
		}
	}
	return chosen, nil
}

func multiSelectText(title string, options []string) ([]string, error) {
	fmt.Println(title)
	for i, opt := range options {
		fmt.Printf("%d) %s\n", i+1, opt)
	}
	fmt.Print("Enter numbers separated by commas (e.g. 1,3,5): ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return nil, nil
	}
	parts := strings.Split(scanner.Text(), ",")
	var chosen []string
	for _, part := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 1 || n > len(options) {
			continue
		}
		chosen = append(chosen, options[n-1])
	}
	return chosen, nil
}
