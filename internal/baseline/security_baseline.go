package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// SecurityBaseline stores hashed snapshots of security-sensitive files and
// lists of security-sensitive artefacts (SUID binaries, sudoers entries).
// Saved to ~/.dsd/security-baseline.json.
// Updated explicitly with: dsd security --save-baseline
// Compared against with: dsd security --drift
type SecurityBaseline struct {
	SavedAt  time.Time `json:"saved_at"`
	Hostname string    `json:"hostname"`
	// SSH config file hashes (path → sha256 hex of file content)
	SSHConfigHashes map[string]string `json:"ssh_config_hashes"`
	// Known SUID binary paths (the list as of baseline time)
	KnownSUIDs []string `json:"known_suids"`
	// Sudoers NOPASSWD entries as of baseline time
	SudoNopasswd []string `json:"sudo_nopasswd"`
	// Suspect cron entries as of baseline time
	SuspectCrons []string `json:"suspect_crons"`
}

// SecurityDiff holds what changed between a saved baseline and the current state.
type SecurityDiff struct {
	NewSUIDs        []string // SUID binaries not in the baseline
	RemovedSUIDs    []string // SUID binaries in baseline but now gone
	NewSudoEntries  []string // new NOPASSWD entries since baseline
	NewCronEntries  []string // new suspect cron entries since baseline
	ChangedSSHFiles []string // SSH config files whose hash changed
	AddedSSHFiles   []string // SSH config files present now but not in the baseline
	RemovedSSHFiles []string // SSH config files in the baseline but now gone
	// true when baseline is missing entirely (first run)
	NoBaseline      bool
	BaselineSavedAt time.Time
}

// HasChanges returns true when any drift was detected. Added and removed SSH
// config files count: an attacker dropping /etc/ssh/sshd_config.d/99-evil.conf
// (PermitRootLogin yes) or deleting a hardening drop-in is exactly the drift
// this is meant to catch.
func (d *SecurityDiff) HasChanges() bool {
	return len(d.NewSUIDs) > 0 || len(d.NewSudoEntries) > 0 ||
		len(d.NewCronEntries) > 0 || len(d.ChangedSSHFiles) > 0 ||
		len(d.AddedSSHFiles) > 0 || len(d.RemovedSSHFiles) > 0
}

// SecurityBaselinePath returns the path to the security baseline file.
// ~/.dsd/security-baseline.json
func SecurityBaselinePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".dsd", "security-baseline.json")
}

// SaveSecurityBaseline writes the baseline to disk atomically.
func SaveSecurityBaseline(b *SecurityBaseline) error {
	path := SecurityBaselinePath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("creating dsd dir: %w", err)
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling security baseline: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".secbase-*.tmp")
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
	return os.Rename(tmpName, path)
}

// LoadSecurityBaseline reads the baseline from disk.
// Returns nil, nil when no baseline exists yet.
func LoadSecurityBaseline() (*SecurityBaseline, error) {
	path := SecurityBaselinePath()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading security baseline: %w", err)
	}
	var b SecurityBaseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parsing security baseline: %w", err)
	}
	return &b, nil
}

// BuildSecurityBaseline creates a baseline from a current SecurityInfo snapshot.
func BuildSecurityBaseline(info *models.SecurityInfo) *SecurityBaseline {
	hostname, _ := os.Hostname()
	b := &SecurityBaseline{
		SavedAt:      time.Now(),
		Hostname:     hostname,
		KnownSUIDs:   info.SUIDBinaries,
		SudoNopasswd: info.SudoNopasswd,
		SuspectCrons: info.SuspectCrons,
	}
	// Hash SSH config files
	b.SSHConfigHashes = hashSSHConfigFiles()
	return b
}

// hashSSHConfigFiles hashes the system SSH server config files.
// Hashes /etc/ssh/sshd_config plus every /etc/ssh/sshd_config.d/*.conf file.
// Returns map[path]sha256hex. Files that don't exist are omitted. Returns an
// empty (non-nil) map when /etc/ssh does not exist (e.g. macOS) — never errors.
func hashSSHConfigFiles() map[string]string {
	hashes := make(map[string]string)

	paths := []string{"/etc/ssh/sshd_config"}
	if matches, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		paths = append(paths, matches...)
	}

	for _, p := range paths {
		data, err := os.ReadFile(filepath.Clean(p))
		if err != nil {
			continue // missing/unreadable file is not an error — just omit it
		}
		sum := sha256.Sum256(data)
		hashes[p] = hex.EncodeToString(sum[:])
	}
	return hashes
}

// DiffSecurityBaseline compares a saved baseline against a current SecurityInfo.
// Returns a SecurityDiff describing what changed.
// If baseline is nil: returns SecurityDiff{NoBaseline: true}.
func DiffSecurityBaseline(baseline *SecurityBaseline, current *models.SecurityInfo) SecurityDiff {
	if baseline == nil {
		return SecurityDiff{NoBaseline: true}
	}

	diff := SecurityDiff{BaselineSavedAt: baseline.SavedAt}

	baseSUIDs := toSet(baseline.KnownSUIDs)
	curSUIDs := toSet(current.SUIDBinaries)
	for _, s := range current.SUIDBinaries {
		if !baseSUIDs[s] {
			diff.NewSUIDs = append(diff.NewSUIDs, s)
		}
	}
	for _, s := range baseline.KnownSUIDs {
		if !curSUIDs[s] {
			diff.RemovedSUIDs = append(diff.RemovedSUIDs, s)
		}
	}

	baseSudo := toSet(baseline.SudoNopasswd)
	for _, s := range current.SudoNopasswd {
		if !baseSudo[s] {
			diff.NewSudoEntries = append(diff.NewSudoEntries, s)
		}
	}

	baseCron := toSet(baseline.SuspectCrons)
	for _, s := range current.SuspectCrons {
		if !baseCron[s] {
			diff.NewCronEntries = append(diff.NewCronEntries, s)
		}
	}

	// SSH config drift — compare the current set of config files against the
	// baseline. Detect three kinds of change: content changed, file removed
	// (baseline had it, gone now), and file added (present now, not in baseline).
	// Earlier this only caught content changes to files in BOTH sets, so a new
	// sshd_config.d/*.conf drop-in or a deleted hardening file slipped through.
	curHashes := hashSSHConfigFilesFn()
	for path, baseHash := range baseline.SSHConfigHashes {
		curHash, ok := curHashes[path]
		switch {
		case !ok:
			diff.RemovedSSHFiles = append(diff.RemovedSSHFiles, path)
		case curHash != baseHash:
			diff.ChangedSSHFiles = append(diff.ChangedSSHFiles, path)
		}
	}
	for path := range curHashes {
		if _, ok := baseline.SSHConfigHashes[path]; !ok {
			diff.AddedSSHFiles = append(diff.AddedSSHFiles, path)
		}
	}
	// Map iteration is unordered — sort for stable output and tests.
	sort.Strings(diff.ChangedSSHFiles)
	sort.Strings(diff.AddedSSHFiles)
	sort.Strings(diff.RemovedSSHFiles)

	return diff
}

// hashSSHConfigFilesFn is the source of current SSH config hashes, overridable
// in tests so drift detection can be exercised without depending on the host's
// /etc/ssh contents.
var hashSSHConfigFilesFn = hashSSHConfigFiles

// toSet converts a slice to a membership set. A nil slice yields an empty set.
func toSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, it := range items {
		set[it] = true
	}
	return set
}
