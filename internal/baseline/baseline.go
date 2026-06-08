package baseline

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/version"
)

type Snapshot struct {
	Hostname  string        `json:"hostname"`
	Timestamp time.Time     `json:"timestamp"`
	Version   string        `json:"version"`
	Checks    []CheckResult `json:"checks"`
}

type CheckResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Value  string `json:"value"`
	Raw    any    `json:"raw,omitempty"`
}

type DiffEntry struct {
	Name         string
	Before       string
	After        string
	StatusChange string
	Changed      bool
	Improved     bool
}

func baselineDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".dsd", "baselines")
}

func latestPath(hostname string) string {
	return filepath.Join(baselineDir(), hostname+"-latest.json")
}

func prevPath(hostname string) string {
	return filepath.Join(baselineDir(), hostname+"-prev.json")
}

func SaveBaseline(snap *Snapshot) error {
	dir := baselineDir()
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("creating baseline dir: %w", err)
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling snapshot: %w", err)
	}

	tsFile := filepath.Join(dir, snap.Hostname+"-"+snap.Timestamp.Format("20060102-150405")+".json")
	tmp, err := os.CreateTemp(dir, ".snap-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, tsFile); err != nil {
		return err
	}

	latest := latestPath(snap.Hostname)
	if _, err := os.Stat(latest); err == nil {
		_ = os.Rename(latest, prevPath(snap.Hostname))
	}

	tmp2, err := os.CreateTemp(dir, ".latest-*.tmp")
	if err != nil {
		return fmt.Errorf("creating latest temp: %w", err)
	}
	tmp2Name := tmp2.Name()
	defer func() { _ = os.Remove(tmp2Name) }()
	if _, err := tmp2.Write(data); err != nil {
		_ = tmp2.Close()
		return err
	}
	if err := tmp2.Close(); err != nil {
		return err
	}
	return os.Rename(tmp2Name, latest)
}

func LoadBaseline(path string) (*Snapshot, error) {
	var (
		data []byte
		err  error
	)
	switch path {
	case "-":
		data, err = io.ReadAll(os.Stdin)
	case "":
		// The empty path means "the last completed run", used by `dsd health
		// --diff` (which runs before the current run is saved). That is the
		// -latest.json file. Reading -prev.json here was an off-by-one: at the
		// start of run N, -latest holds run N-1 and -prev holds run N-2, so the
		// diff compared against TWO runs ago and showed nothing on the 2nd run.
		hostname, _ := os.Hostname()
		data, err = os.ReadFile(latestPath(hostname))
	default:
		data, err = os.ReadFile(filepath.Clean(path))
	}
	if err != nil {
		return nil, fmt.Errorf("reading baseline: %w", err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parsing baseline: %w", err)
	}
	return &snap, nil
}

func BuildSnapshot(results []runner.Result, insights []models.Insight) *Snapshot {
	hostname, _ := os.Hostname()
	snap := &Snapshot{
		Hostname:  hostname,
		Timestamp: time.Now(),
		Version:   version.Version,
	}
	for _, r := range results {
		cr := CheckResult{Name: r.Name, Raw: r.Data, Status: "OK"}
		for _, ins := range insights {
			if ins.Check == r.Name {
				cr.Status = ins.Level
				cr.Value = ins.Message
				break
			}
		}
		snap.Checks = append(snap.Checks, cr)
	}
	return snap
}

func ComputeDiff(before, after *Snapshot) []DiffEntry {
	beforeMap := make(map[string]CheckResult, len(before.Checks))
	for _, c := range before.Checks {
		beforeMap[c.Name] = c
	}

	statusOrder := map[string]int{"OK": 0, "INFO": 0, "WARN": 1, "CRIT": 2}

	var degraded, improved, unchanged []DiffEntry
	for _, ac := range after.Checks {
		bc := beforeMap[ac.Name]
		d := DiffEntry{
			Name:         ac.Name,
			Before:       bc.Status + " " + bc.Value,
			After:        ac.Status + " " + ac.Value,
			StatusChange: bc.Status + "->" + ac.Status,
			Changed:      bc.Status != ac.Status,
			Improved:     statusOrder[ac.Status] < statusOrder[bc.Status],
		}
		switch {
		case d.Changed && !d.Improved:
			degraded = append(degraded, d)
		case d.Changed && d.Improved:
			improved = append(improved, d)
		default:
			unchanged = append(unchanged, d)
		}
	}

	result := make([]DiffEntry, 0, len(after.Checks))
	result = append(result, degraded...)
	result = append(result, improved...)
	result = append(result, unchanged...)
	return result
}
