package tui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
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
	s := m.title + "\n\n"
	for i, opt := range m.options {
		cursor := "  "
		if m.cursor == i {
			cursor = "> "
		}
		s += cursor + opt + "\n"
	}
	s += "\n↑/↓ navigate  enter select  q quit\n"
	return s
}

func RunSingleSelect(title string, options []string) (string, error) {
	if !IsTTY() {
		return singleSelectText(title, options)
	}
	m := SingleSelectModel{title: title, options: options}
	p := tea.NewProgram(m)
	result, err := p.Run()
	if err != nil {
		return "", err
	}
	return result.(SingleSelectModel).chosen, nil
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
			m.done = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m MultiSelectModel) View() string {
	s := m.title + "\n\n"
	for i, opt := range m.options {
		cursor := "  "
		if m.cursor == i {
			cursor = "> "
		}
		checked := "[ ]"
		if m.selected[i] {
			checked = "[x]"
		}
		s += cursor + checked + " " + opt + "\n"
	}
	s += "\n↑/↓ navigate  space toggle  enter confirm  q quit\n"
	return s
}

func RunMultiSelect(title string, options []string) ([]string, error) {
	if !IsTTY() {
		return multiSelectText(title, options)
	}
	m := MultiSelectModel{
		title:    title,
		options:  options,
		selected: make([]bool, len(options)),
	}
	p := tea.NewProgram(m)
	result, err := p.Run()
	if err != nil {
		return nil, err
	}
	final := result.(MultiSelectModel)
	var chosen []string
	for i, sel := range final.selected {
		if sel {
			chosen = append(chosen, options[i])
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
