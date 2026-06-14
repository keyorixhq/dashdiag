package source

import (
	"fmt"
	"os"
	"path/filepath"
)

// On-disk index records (files/index.json, commands/index.json).
type fileIndexEntry struct {
	Path     string `json:"path"`
	Blob     string `json:"blob,omitempty"`
	NotExist bool   `json:"not_exist,omitempty"`
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

// Save writes the bundle to dir in the raw-v1 layout (creating dir if needed).
func (b *Bundle) Save(dir string) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, sub := range []string{"files/blobs", "commands/blobs"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
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
		e := fileIndexEntry{Path: path, NotExist: rec.notExist, Err: rec.errText}
		if !rec.notExist && rec.errText == "" {
			blob := fmt.Sprintf("files/blobs/%04d", n)
			n++
			if err := os.WriteFile(filepath.Join(dir, blob), rec.data, 0o644); err != nil {
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

	// Commands
	var cidx []cmdIndexEntry
	cn := 0
	for _, key := range sortedKeys(b.cmds) {
		rec := b.cmds[key]
		e := cmdIndexEntry{Argv: splitKey(key), Exit: rec.res.ExitCode, Absent: rec.absent, Err: rec.errText}
		if len(rec.res.Stdout) > 0 {
			e.StdoutBlob = fmt.Sprintf("commands/blobs/%04d.out", cn)
			if err := os.WriteFile(filepath.Join(dir, e.StdoutBlob), rec.res.Stdout, 0o644); err != nil {
				return err
			}
		}
		if len(rec.res.Stderr) > 0 {
			e.StderrBlob = fmt.Sprintf("commands/blobs/%04d.err", cn)
			if err := os.WriteFile(filepath.Join(dir, e.StderrBlob), rec.res.Stderr, 0o644); err != nil {
				return err
			}
		}
		cn++
		cidx = append(cidx, e)
	}
	return writeJSON(filepath.Join(dir, "commands/index.json"), cidx)
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
		rec := fileRec{notExist: e.NotExist, errText: e.Err}
		if e.Blob != "" {
			data, err := os.ReadFile(filepath.Join(dir, e.Blob))
			if err != nil {
				return nil, err
			}
			rec.data = data
		}
		b.files[e.Path] = rec
	}

	_ = readJSON(filepath.Join(dir, "globs.json"), &b.globs)
	_ = readJSON(filepath.Join(dir, "dirs.json"), &b.dirs)

	var cidx []cmdIndexEntry
	if err := readJSON(filepath.Join(dir, "commands/index.json"), &cidx); err != nil {
		return nil, err
	}
	for _, e := range cidx {
		rec := cmdRec{res: Result{ExitCode: e.Exit}, absent: e.Absent, errText: e.Err}
		if e.StdoutBlob != "" {
			rec.res.Stdout, _ = os.ReadFile(filepath.Join(dir, e.StdoutBlob))
		}
		if e.StderrBlob != "" {
			rec.res.Stderr, _ = os.ReadFile(filepath.Join(dir, e.StderrBlob))
		}
		if len(e.Argv) > 0 {
			b.cmds[cmdKey(e.Argv[0], e.Argv[1:])] = rec
		}
	}
	return b, nil
}
