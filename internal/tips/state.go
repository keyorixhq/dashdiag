package tips

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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

// maxStateFileBytes bounds how large ~/.dsd/state.json may be before
// LoadState reads it. The real file is a handful of counters and a short
// tips-shown history — a few KiB at most; this is generous headroom while
// stopping an oversized or symlinked file from being read fully into memory
// before validation.
const maxStateFileBytes = 4 << 20 // 4 MiB

func LoadState() (*State, error) {
	path := stateFilePath()
	fi, statErr := os.Stat(path)
	if os.IsNotExist(statErr) {
		return &State{
			TipsEnabled:   true,
			CommandCounts: make(map[string]int),
		}, nil
	}
	if statErr != nil {
		return nil, statErr
	}
	if fi.Size() > maxStateFileBytes {
		return nil, fmt.Errorf("state file %q is %d bytes, exceeds %d byte limit", path, fi.Size(), maxStateFileBytes)
	}
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- fixed ~/.dsd/state.json path, size-checked above
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
	return slices.Contains(s.ShownMilestones, m)
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
