package source

import (
	"errors"
	"io/fs"
	"sync"
)

// Manifest is the bundle's metadata header.
type Manifest struct {
	Format  string `json:"format"`
	Host    string `json:"host,omitempty"`
	OS      string `json:"os,omitempty"`
	Kernel  string `json:"kernel,omitempty"`
	DsdVer  string `json:"dsd_version,omitempty"`
	Created string `json:"created,omitempty"`
	Note    string `json:"note,omitempty"`
}

// fileRec is a recorded file read: bytes on success, or a recorded error so that
// "absent at capture time" replays as absent rather than as a recording gap.
type fileRec struct {
	data       []byte
	notExist   bool
	permission bool // read failed with a permission error (present but unreadable)
	errText    string
}

// cmdRec is a recorded command: its Result plus whether the tool was absent.
type cmdRec struct {
	res     Result
	absent  bool
	errText string
}

// Bundle is the in-memory, persistable record of every system input touched
// during a capture. Safe for concurrent use — collectors run in parallel.
type Bundle struct {
	Manifest Manifest

	mu    sync.RWMutex
	files map[string]fileRec
	globs map[string][]string
	dirs  map[string][]string
	cmds  map[string]cmdRec
}

// NewBundle returns an empty bundle stamped with the current format version.
func NewBundle() *Bundle {
	return &Bundle{
		Manifest: Manifest{Format: FormatVersion},
		files:    map[string]fileRec{},
		globs:    map[string][]string{},
		dirs:     map[string][]string{},
		cmds:     map[string]cmdRec{},
	}
}

func (b *Bundle) putFile(path string, data []byte, err error) {
	rec := fileRec{}
	switch {
	case err == nil:
		rec.data = append([]byte(nil), data...)
	case errors.Is(err, fs.ErrNotExist):
		rec.notExist = true
	case errors.Is(err, fs.ErrPermission):
		// Present but unreadable. Preserve the permission identity so replay can
		// reconstruct an os.IsPermission-satisfying error (collectors branch on it,
		// e.g. "config present but not readable").
		rec.permission = true
		rec.errText = err.Error()
	default:
		rec.errText = err.Error()
	}
	b.mu.Lock()
	b.files[cleanPath(path)] = rec
	b.mu.Unlock()
}

func (b *Bundle) getFile(path string) (fileRec, bool) {
	b.mu.RLock()
	rec, ok := b.files[cleanPath(path)]
	b.mu.RUnlock()
	return rec, ok
}

// PutFile records a synthetic file in the bundle (success, with data). Used to
// embed auxiliary artifacts such as the rendered health JSON under a sentinel
// path, so a raw bundle carries both the inputs and the report they produced.
func (b *Bundle) PutFile(path string, data []byte) { b.putFile(path, data, nil) }

func (b *Bundle) putGlob(pattern string, matches []string) {
	b.mu.Lock()
	b.globs[pattern] = append([]string(nil), matches...)
	b.mu.Unlock()
}

func (b *Bundle) getGlob(pattern string) ([]string, bool) {
	b.mu.RLock()
	m, ok := b.globs[pattern]
	b.mu.RUnlock()
	return m, ok
}

func (b *Bundle) putDir(dir string, names []string) {
	b.mu.Lock()
	b.dirs[cleanPath(dir)] = append([]string(nil), names...)
	b.mu.Unlock()
}

func (b *Bundle) getDir(dir string) ([]string, bool) {
	b.mu.RLock()
	n, ok := b.dirs[cleanPath(dir)]
	b.mu.RUnlock()
	return n, ok
}

func (b *Bundle) putCmd(name string, args []string, res Result, err error) {
	rec := cmdRec{res: res}
	if err != nil {
		rec.absent = true
		rec.errText = err.Error()
	}
	b.mu.Lock()
	b.cmds[cmdKey(name, args)] = rec
	b.mu.Unlock()
}

func (b *Bundle) getCmd(name string, args []string) (cmdRec, bool) {
	b.mu.RLock()
	rec, ok := b.cmds[cmdKey(name, args)]
	b.mu.RUnlock()
	return rec, ok
}
