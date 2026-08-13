package source

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// On-disk index records (files/index.json, commands/index.json).
type fileIndexEntry struct {
	Path     string `json:"path"`
	Blob     string `json:"blob,omitempty"`
	NotExist bool   `json:"not_exist,omitempty"`
	Perm     bool   `json:"perm,omitempty"` // present but unreadable (permission denied)
	Err      string `json:"err,omitempty"`
}

type cmdIndexEntry struct {
	Argv       []string `json:"argv"`
	StdoutBlob string   `json:"stdout,omitempty"`
	StderrBlob string   `json:"stderr,omitempty"`
	Exit       int      `json:"exit"`
	Absent     bool     `json:"absent,omitempty"`
	Err        string   `json:"err,omitempty"`
}

type linkIndexEntry struct {
	Path     string `json:"path"`
	Target   string `json:"target,omitempty"`
	NotExist bool   `json:"not_exist,omitempty"`
	Perm     bool   `json:"perm,omitempty"`
	Err      string `json:"err,omitempty"`
}

type statIndexEntry struct {
	Path     string   `json:"path"`
	Meta     FileMeta `json:"meta"`
	NotExist bool     `json:"not_exist,omitempty"`
	Perm     bool     `json:"perm,omitempty"`
	Err      string   `json:"err,omitempty"`
}

type statfsIndexEntry struct {
	Path     string     `json:"path"`
	Info     StatfsInfo `json:"info"`
	NotExist bool       `json:"not_exist,omitempty"`
	Perm     bool       `json:"perm,omitempty"`
	Err      string     `json:"err,omitempty"`
}

// Save writes the bundle to dir in the raw-v1 layout (creating dir if needed).
func (b *Bundle) Save(dir string) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// 0o700/0o600: a capture bundle can carry sensitive host data (hostnames,
	// IPs, disk serials, journald lines, and any secrets in captured
	// files/commands — see cmd/capture_raw.go's own doc comment on this).
	// Save() is exported and has no control over what directory a caller
	// points it at, so it must not rely on the caller (today, only
	// SaveTarball's private os.MkdirTemp dir) to keep it private — write
	// restrictively here too, defense in depth.
	for _, sub := range []string{"files/blobs", "commands/blobs"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(dir, "manifest.json"), b.Manifest); err != nil {
		return err
	}

	// Files
	var fidx []fileIndexEntry
	n := 0
	for _, path := range sortedKeys(b.files) {
		rec := b.files[path]
		e := fileIndexEntry{Path: path, NotExist: rec.notExist, Perm: rec.permission, Err: rec.errText}
		if !rec.notExist && rec.errText == "" {
			blob := fmt.Sprintf("files/blobs/%04d", n)
			n++
			if err := os.WriteFile(filepath.Join(dir, blob), rec.data, 0o600); err != nil {
				return err
			}
			e.Blob = blob
		}
		fidx = append(fidx, e)
	}
	if err := writeJSON(filepath.Join(dir, "files/index.json"), fidx); err != nil {
		return err
	}

	// Globs and dirs (plain maps)
	if err := writeJSON(filepath.Join(dir, "globs.json"), b.globs); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "dirs.json"), b.dirs); err != nil {
		return err
	}

	// Links, stats, statfs — inline metadata sections, no blobs.
	if err := b.saveInlineMeta(dir); err != nil {
		return err
	}

	// Commands
	var cidx []cmdIndexEntry
	cn := 0
	for _, key := range sortedKeys(b.cmds) {
		rec := b.cmds[key]
		e := cmdIndexEntry{Argv: splitKey(key), Exit: rec.res.ExitCode, Absent: rec.absent, Err: rec.errText}
		if len(rec.res.Stdout) > 0 {
			e.StdoutBlob = fmt.Sprintf("commands/blobs/%04d.out", cn)
			if err := os.WriteFile(filepath.Join(dir, e.StdoutBlob), rec.res.Stdout, 0o600); err != nil {
				return err
			}
		}
		if len(rec.res.Stderr) > 0 {
			e.StderrBlob = fmt.Sprintf("commands/blobs/%04d.err", cn)
			if err := os.WriteFile(filepath.Join(dir, e.StderrBlob), rec.res.Stderr, 0o600); err != nil {
				return err
			}
		}
		cn++
		cidx = append(cidx, e)
	}
	return writeJSON(filepath.Join(dir, "commands/index.json"), cidx)
}

// saveInlineMeta writes the three inline (blob-free) metadata sections —
// symlink targets, os.Stat metadata, and syscall.Statfs stats. Split out of Save
// to keep it under the funlen limit; callers hold b.mu.RLock.
func (b *Bundle) saveInlineMeta(dir string) error {
	lidx := make([]linkIndexEntry, 0, len(b.links))
	for _, path := range sortedKeys(b.links) {
		rec := b.links[path]
		lidx = append(lidx, linkIndexEntry{
			Path: path, Target: rec.target, NotExist: rec.notExist, Perm: rec.permission, Err: rec.errText,
		})
	}
	if err := writeJSON(filepath.Join(dir, "links.json"), lidx); err != nil {
		return err
	}

	sidx := make([]statIndexEntry, 0, len(b.stats))
	for _, path := range sortedKeys(b.stats) {
		rec := b.stats[path]
		sidx = append(sidx, statIndexEntry{
			Path: path, Meta: rec.meta, NotExist: rec.notExist, Perm: rec.permission, Err: rec.errText,
		})
	}
	if err := writeJSON(filepath.Join(dir, "stats.json"), sidx); err != nil {
		return err
	}

	sfidx := make([]statfsIndexEntry, 0, len(b.statfss))
	for _, path := range sortedKeys(b.statfss) {
		rec := b.statfss[path]
		sfidx = append(sfidx, statfsIndexEntry{
			Path: path, Info: rec.info, NotExist: rec.notExist, Perm: rec.permission, Err: rec.errText,
		})
	}
	return writeJSON(filepath.Join(dir, "statfs.json"), sfidx)
}

// safeBlobJoin joins dir with an index entry's blob path (fileIndexEntry.Blob,
// cmdIndexEntry.StdoutBlob/StderrBlob), rejecting the result if it escapes
// dir. These fields are attacker-controlled JSON string values read straight
// out of a bundle's index files — not tar member names, so the traversal
// guard tarball.go applies during extraction never sees them. A legitimate
// bundle only ever writes fixed-shape values here (files/blobs/%04d,
// commands/blobs/%04d.out/.err — see Save), so any value that resolves
// outside dir is a crafted bundle, never a real one.
func safeBlobJoin(dir, rel string) (string, error) {
	full := filepath.Join(dir, rel)
	base := filepath.Clean(dir)
	if full != base && !strings.HasPrefix(full, base+string(filepath.Separator)) {
		return "", fmt.Errorf("source: blob path %q escapes bundle directory", rel)
	}
	return full, nil
}

// Load reads a bundle previously written by Save.
func Load(dir string) (*Bundle, error) {
	b := NewBundle()
	if err := readJSON(filepath.Join(dir, "manifest.json"), &b.Manifest); err != nil {
		return nil, err
	}
	if b.Manifest.Format != FormatVersion {
		return nil, fmt.Errorf("source: bundle format %q, this binary expects %q", b.Manifest.Format, FormatVersion)
	}

	var fidx []fileIndexEntry
	if err := readJSON(filepath.Join(dir, "files/index.json"), &fidx); err != nil {
		return nil, err
	}
	for _, e := range fidx {
		rec := fileRec{notExist: e.NotExist, permission: e.Perm, errText: e.Err}
		if e.Blob != "" {
			blobPath, err := safeBlobJoin(dir, e.Blob)
			if err != nil {
				return nil, err
			}
			data, err := os.ReadFile(blobPath)
			if err != nil {
				return nil, err
			}
			rec.data = data
		}
		b.files[e.Path] = rec
	}

	_ = readJSON(filepath.Join(dir, "globs.json"), &b.globs)
	_ = readJSON(filepath.Join(dir, "dirs.json"), &b.dirs)

	// Symlinks — optional so older bundles (pre-links) still load.
	var lidx []linkIndexEntry
	_ = readJSON(filepath.Join(dir, "links.json"), &lidx)
	for _, e := range lidx {
		b.links[e.Path] = linkRec{target: e.Target, notExist: e.NotExist, permission: e.Perm, errText: e.Err}
	}

	// Stats — optional so older bundles (pre-stats) still load.
	var sidx []statIndexEntry
	_ = readJSON(filepath.Join(dir, "stats.json"), &sidx)
	for _, e := range sidx {
		b.stats[e.Path] = statRec{meta: e.Meta, notExist: e.NotExist, permission: e.Perm, errText: e.Err}
	}

	// Statfs — optional so older bundles (pre-statfs) still load.
	var sfidx []statfsIndexEntry
	_ = readJSON(filepath.Join(dir, "statfs.json"), &sfidx)
	for _, e := range sfidx {
		b.statfss[e.Path] = statfsRec{info: e.Info, notExist: e.NotExist, permission: e.Perm, errText: e.Err}
	}

	var cidx []cmdIndexEntry
	if err := readJSON(filepath.Join(dir, "commands/index.json"), &cidx); err != nil {
		return nil, err
	}
	for _, e := range cidx {
		rec := cmdRec{res: Result{ExitCode: e.Exit}, absent: e.Absent, errText: e.Err}
		if e.StdoutBlob != "" {
			if p, err := safeBlobJoin(dir, e.StdoutBlob); err == nil {
				rec.res.Stdout, _ = os.ReadFile(p)
			}
		}
		if e.StderrBlob != "" {
			if p, err := safeBlobJoin(dir, e.StderrBlob); err == nil {
				rec.res.Stderr, _ = os.ReadFile(p)
			}
		}
		if len(e.Argv) > 0 {
			b.cmds[cmdKey(e.Argv[0], e.Argv[1:])] = rec
		}
	}
	return b, nil
}
