package baseline

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
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

// writeAndCloseFn writes data to f and closes it, returning any error from
// either step (closing f on a write failure first so no fd leaks). A
// package-level var — like hashSSHConfigFilesFn below — so tests can
// simulate a write/close failure on an already-successfully-created temp
// file, a state not otherwise reachable without a real disk-full/IO error.
var writeAndCloseFn = func(f *os.File, data []byte) error {
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func baselineDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".dsd", "baselines")
}

// safeHostname strips path-unsafe characters from a hostname before it is used
// as a filename component. Bundles arriving via dsd replay carry a
// manifest-supplied hostname that is attacker-controlled; letting it flow into
// filepath.Join unsanitized allows writes outside ~/.dsd/baselines/.
func safeHostname(h string) string {
	safe := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == '\x00' {
			return '_'
		}
		return r
	}, h)
	if safe == "" || safe == "." || safe == ".." {
		return "unknown-host"
	}
	return safe
}

func latestPath(hostname string) string {
	dir := baselineDir()
	full := filepath.Join(dir, safeHostname(hostname)+"-latest.json")
	if !strings.HasPrefix(full, dir) {
		return filepath.Join(dir, "unknown-host-latest.json")
	}
	return full
}

func prevPath(hostname string) string {
	dir := baselineDir()
	full := filepath.Join(dir, safeHostname(hostname)+"-prev.json")
	if !strings.HasPrefix(full, dir) {
		return filepath.Join(dir, "unknown-host-prev.json")
	}
	return full
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

	tsFile := filepath.Join(dir, safeHostname(snap.Hostname)+"-"+snap.Timestamp.Format("20060102-150405")+".json")
	if !strings.HasPrefix(tsFile, dir) {
		return fmt.Errorf("baseline path %q escapes baseline directory", tsFile)
	}
	tmp, err := os.CreateTemp(dir, ".snap-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := writeAndCloseFn(tmp, data); err != nil {
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
	if err := writeAndCloseFn(tmp2, data); err != nil {
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

// statusRank orders insight levels so BuildSnapshot can keep the worst per check.
func statusRank(level string) int {
	switch level {
	case "CRIT":
		return 3
	case "WARN":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

func BuildSnapshot(results []runner.Result, insights []models.Insight) *Snapshot {
	hostname := platform.Hostname() // honors the replay identity override (dsd diff)
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
		worstRank := -1
		for _, ins := range insights {
			// Match by the base check name so a subsystem-qualified insight
			// ("Network/DNS", "Memory/Slab", "CPU Load/Steal") still attaches to its
			// collector ("Network", "Memory", "CPU Load"). And keep the WORST level,
			// not the first matched — otherwise a CRIT hidden behind an earlier
			// INFO/WARN (or a qualified-Check CRIT that never matched) under-recorded
			// the check in the baseline and hid the degradation from drift detection.
			base := ins.Check
			if i := strings.IndexByte(base, '/'); i >= 0 {
				base = base[:i]
			}
			if base != r.Name {
				continue
			}
			hasInsight = true
			if rank := statusRank(ins.Level); rank > worstRank {
				worstRank = rank
				cr.Status = ins.Level
				cr.Value = ins.Message
			}
		}
		// Mirror live health (render.shouldHideRow): a collector that reports
		// itself unavailable (Available=false) and carries no insight is "absent /
		// not applicable" — recording it as a passing check produced phantom
		// "X ✅ OK" rows in dsd health --report (e.g. Ceph with the CLI installed
		// but no cluster, Auth with no sshd). An insight referencing the check is
		// an actionable finding and must never be dropped, so keep those.
		// runner.IsAvailable is the shared definition used by live health too
		// (render.shouldHideRow) so --report and live dsd health hide the same
		// not-applicable rows. An insight is an actionable finding and is kept
		// regardless.
		if !hasInsight && !runner.IsAvailable(r.Data) {
			continue
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

	// Reuse statusRank (not a second, locally-defined ordering) so a collector
	// that starts/stops erroring (OK<->INFO) ranks correctly relative to OK
	// instead of tying with it. A prior local `statusOrder` map here scored
	// INFO the same as OK (0), which made an INFO->OK recovery register as
	// "degraded" (equal rank -> Improved=false) — same fail-open class as the
	// --report table collapsing INFO to OK, just in the diff engine.

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
			// A brand-new check. A new problem (WARN/CRIT) — or a newly-erroring
			// collector (INFO) — is a degraded change; a new healthy check is just
			// added coverage, not a status change — flagging it as "->OK degraded"
			// (the old zero-value bug) was wrong.
			d.StatusChange = "new->" + ac.Status
			if statusRank(ac.Status) > 0 {
				d.Changed = true
				degraded = append(degraded, d)
			} else {
				unchanged = append(unchanged, d)
			}
		default:
			d.StatusChange = bc.Status + "->" + ac.Status
			d.Changed = bc.Status != ac.Status
			d.Improved = statusRank(ac.Status) < statusRank(bc.Status)
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
		if seen[bc.Name] || statusRank(bc.Status) == 0 {
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
