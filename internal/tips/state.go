package tips

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type State struct {
	TotalRuns       int            `json:"total_runs"`
	ShownMilestones []int          `json:"shown_milestones"`
	LastTipDate     string         `json:"last_tip_date"`
	TipIndex        int            `json:"tip_index"`
	TipsEnabled     bool           `json:"tips_enabled"`
	NPSDone         bool           `json:"nps_done"`
	NPSScore        string         `json:"nps_score"`
	NPSReason       string         `json:"nps_reason"`
	HookInstalled   bool           `json:"hook_installed"`
	CurrentStreak   int            `json:"current_streak"`
	LongestStreak   int            `json:"longest_streak"`
	LastRunDate     string         `json:"last_run_date"`
	LastVersion     string         `json:"last_version"`
	TrialOffered    bool           `json:"trial_offered"`
	PipedRuns       int            `json:"piped_runs"`
	CommandCounts   map[string]int `json:"command_counts"`
	ErrorExits      int            `json:"error_exits"`
}

func stateFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".dsd/state.json"
	}
	return filepath.Join(home, ".dsd", "state.json")
}

func LoadState() (*State, error) {
	path := stateFilePath()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &State{
			TipsEnabled:   true,
			CommandCounts: make(map[string]int),
		}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if s.CommandCounts == nil {
		s.CommandCounts = make(map[string]int)
	}
	return &s, nil
}

func (s *State) Save() error {
	path := stateFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *State) HasShownMilestone(m int) bool {
	for _, v := range s.ShownMilestones {
		if v == m {
			return true
		}
	}
	return false
}

func (s *State) MarkMilestone(m int) {
	if !s.HasShownMilestone(m) {
		s.ShownMilestones = append(s.ShownMilestones, m)
	}
}

// Streaks use negative values in ShownMilestones to avoid collision with run counts.
func (s *State) HasShownStreak(days int) bool {
	return s.HasShownMilestone(-days)
}

func (s *State) MarkStreak(days int) {
	s.MarkMilestone(-days)
}

func (s *State) IncrementCommand(name string) {
	if s.CommandCounts == nil {
		s.CommandCounts = make(map[string]int)
	}
	s.CommandCounts[name]++
}
