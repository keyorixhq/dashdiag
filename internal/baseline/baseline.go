package baseline

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
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
		// Skip collectors that gated themselves off (nil data, no error) — the
		// "absent / not applicable on this platform" signal. Recording them as a
		// passing check produced phantom rows (e.g. macOS-only "Launchd ✅ OK"
		// in a Linux report).
		if r.Data == nil && r.Err == nil {
			continue
		}
		cr := CheckResult{Name: r.Name, Raw: r.Data, Status: "OK"}
		hasInsight := false
		for _, ins := range insights {
			if ins.Check == r.Name {
				cr.Status = ins.Level
				cr.Value = ins.Message
				hasInsight = true
				break
			}
		}
		// Mirror live health (render.shouldHideRow): a collector that reports
		// itself unavailable (Available=false) and carries no insight is "absent /
		// not applicable" — recording it as a passing check produced phantom
		// "X ✅ OK" rows in dsd health --report (e.g. Ceph with the CLI installed
		// but no cluster, Auth with no sshd). An insight referencing the check is
		// an actionable finding and must never be dropped, so keep those.
		if !hasInsight && !resultAvailable(r.Data) {
			continue
		}
		snap.Checks = append(snap.Checks, cr)
	}
	return snap
}

// resultAvailable reports whether a collector result should be treated as
// "present" for snapshot purposes. It is the snapshot-side twin of
// render.isAvailable — kept in sync deliberately so dsd health --report and live
// dsd health hide the same not-applicable rows. (baseline cannot import render:
// render imports baseline.) Collectors that gate themselves off on a platform
// set Available=false; nil data is already handled by the caller.
func resultAvailable(data interface{}) bool {
	if data == nil {
		return false
	}
	if a, ok := data.(interface{ IsAvailable() bool }); ok {
		return a.IsAvailable()
	}
	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return true // unknown type — show by default
	}
	f := v.FieldByName("Available")
	if !f.IsValid() || f.Kind() != reflect.Bool {
		return true // no Available field — always show (e.g. CPU, Memory, NVMe)
	}
	return f.Bool()
}

func ComputeDiff(before, after *Snapshot) []DiffEntry {
	beforeMap := make(map[string]CheckResult, len(before.Checks))
	for _, c := range before.Checks {
		beforeMap[c.Name] = c
	}

	statusOrder := map[string]int{"OK": 0, "INFO": 0, "WARN": 1, "CRIT": 2}

	var degraded, improved, unchanged []DiffEntry
	seen := make(map[string]bool, len(after.Checks))
	for _, ac := range after.Checks {
		seen[ac.Name] = true
		bc, existed := beforeMap[ac.Name]
		d := DiffEntry{
			Name:   ac.Name,
			Before: bc.Status + " " + bc.Value,
			After:  ac.Status + " " + ac.Value,
		}
		switch {
		case !existed:
			// A brand-new check. A new problem (WARN/CRIT) is a degraded change;
			// a new healthy check is just added coverage, not a status change —
			// flagging it as "->OK degraded" (the old zero-value bug) was wrong.
			d.StatusChange = "new->" + ac.Status
			if statusOrder[ac.Status] > 0 {
				d.Changed = true
				degraded = append(degraded, d)
			} else {
				unchanged = append(unchanged, d)
			}
		default:
			d.StatusChange = bc.Status + "->" + ac.Status
			d.Changed = bc.Status != ac.Status
			d.Improved = statusOrder[ac.Status] < statusOrder[bc.Status]
			switch {
			case d.Changed && !d.Improved:
				degraded = append(degraded, d)
			case d.Changed && d.Improved:
				improved = append(improved, d)
			default:
				unchanged = append(unchanged, d)
			}
		}
	}

	// Checks present in the baseline but gone from the current run. A vanished
	// WARN/CRIT must be surfaced — silently dropping it (the old loop only walked
	// after.Checks) hid real drift, e.g. a previously-CRIT mount no longer
	// reported. Vanished healthy checks are benign and left out to avoid noise.
	for _, bc := range before.Checks {
		if seen[bc.Name] || statusOrder[bc.Status] == 0 {
			continue
		}
		degraded = append(degraded, DiffEntry{
			Name:         bc.Name,
			Before:       bc.Status + " " + bc.Value,
			After:        "absent",
			StatusChange: bc.Status + "->absent",
			Changed:      true,
		})
	}

	result := make([]DiffEntry, 0, len(degraded)+len(improved)+len(unchanged))
	result = append(result, degraded...)
	result = append(result, improved...)
	result = append(result, unchanged...)
	return result
}
