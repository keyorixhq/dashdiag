package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func goldenDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".dsd", "golden")
}

func goldenPath(name string) string {
	return filepath.Join(goldenDir(), name+".json")
}

// SaveGolden saves a snapshot as a named golden baseline.
// Golden baselines are stable reference points — unlike rolling latest/prev,
// they are only updated explicitly via 'dsd baseline save'.
func SaveGolden(snap *Snapshot, name string) error {
	dir := goldenDir()
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("creating golden dir: %w", err)
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	path := goldenPath(name)
	tmp, err := os.CreateTemp(dir, ".golden-*.tmp")
	if err != nil {
		return err
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
	return os.Rename(tmpName, path)
}

// LoadGolden loads a named golden baseline.
func LoadGolden(name string) (*Snapshot, error) {
	data, err := os.ReadFile(goldenPath(name)) // #nosec G304 -- name comes from CLI arg, validated by cobra
	if err != nil {
		return nil, fmt.Errorf("golden baseline %q not found — run 'dsd baseline save %s' first", name, name)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parsing golden baseline %q: %w", name, err)
	}
	return &snap, nil
}

// ListGolden returns all saved golden baseline names.
func ListGolden() ([]string, error) {
	entries, err := os.ReadDir(goldenDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name()[:len(e.Name())-5])
		}
	}
	return names, nil
}

// DriftEntry represents a parameter that changed value between snapshots,
// even if its health status did not change.
type DriftEntry struct {
	Check  string
	Param  string
	Before interface{}
	After  interface{}
}

// ComputeSysctlDrift compares raw sysctl values between two snapshots.
// Returns parameters whose numeric values changed, regardless of status.
// Skips pid_count (changes every run) and fields absent on current system (value 0 or -1).
func ComputeSysctlDrift(golden, current *Snapshot) []DriftEntry {
	goldenRaw := extractSysctlRaw(golden)
	currentRaw := extractSysctlRaw(current)
	if goldenRaw == nil || currentRaw == nil {
		return nil
	}

	// Fields excluded from drift detection — change too frequently or are OS-specific
	skip := map[string]bool{
		"pid_count":     true, // changes every run
		"status":        true, // metadata, not a tunable
		"status_reason": true,
		"workload":      true,
	}

	var drift []DriftEntry
	for key, gVal := range goldenRaw {
		if skip[key] {
			continue
		}
		cVal, ok := currentRaw[key]
		if !ok {
			continue
		}
		// JSON numbers unmarshal as float64
		gf, gok := gVal.(float64)
		cf, cok := cVal.(float64)
		if !gok || !cok {
			continue
		}
		// Skip fields absent on current OS (0 or -1 means not available)
		if cf == 0 || cf == -1 {
			continue
		}
		if gf != cf {
			drift = append(drift, DriftEntry{
				Check:  "Sysctl",
				Param:  key,
				Before: int(gf),
				After:  int(cf),
			})
		}
	}
	return drift
}

// extractSysctlRaw finds the Sysctl check's Raw field and returns it as a map.
// Handles both JSON-decoded maps and live Go structs by normalising through JSON.
func extractSysctlRaw(snap *Snapshot) map[string]interface{} {
	for _, c := range snap.Checks {
		if c.Name != "Sysctl" || c.Raw == nil {
			continue
		}
		// Normalise to map via JSON round-trip.
		// c.Raw may be a map[string]interface{} (loaded from disk)
		// or a live Go struct (*models.SysctlInfo) from a fresh health run.
		data, err := json.Marshal(c.Raw)
		if err != nil {
			return nil
		}
		var m map[string]interface{}
		if err := json.Unmarshal(data, &m); err != nil {
			return nil
		}
		return m
	}
	return nil
}
