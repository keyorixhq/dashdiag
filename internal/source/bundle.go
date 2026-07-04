package source

import (
	"errors"
	"io/fs"
	"os/exec"
	"strings"
	"sync"
)

// Manifest is the bundle's metadata header.
type Manifest struct {
	Format string `json:"format"`
	Host   string `json:"host,omitempty"`
	OS     string `json:"os,omitempty"`
	GOOS   string `json:"goos,omitempty"` // capture-time runtime.GOOS — for the replay platform-match guard
	// DistroID / InitSystem are the captured host's /etc/os-release ID and init system,
	// so `dsd replay`'s fix-hint adaptation reflects the CAPTURED host's package manager
	// / init system, not the box doing the replay. Empty in older bundles → replay falls
	// back to live detection.
	DistroID   string `json:"distro_id,omitempty"`
	InitSystem string `json:"init_system,omitempty"`
	Kernel     string `json:"kernel,omitempty"`
	DsdVer     string `json:"dsd_version,omitempty"`
	Created    string `json:"created,omitempty"`
	Note       string `json:"note,omitempty"`
}

// PlatformFamily returns the captured host's OS family ("linux", "darwin",
// "windows", …). It prefers the recorded GOOS; for older bundles that predate the
// field it infers from the human OS string (defaulting to "linux", since a missing
// GOOS almost always means a Linux capture from before the field existed).
func (m Manifest) PlatformFamily() string {
	if m.GOOS != "" {
		return m.GOOS
	}
	os := strings.ToLower(m.OS)
	switch {
	case strings.Contains(os, "macos"), strings.Contains(os, "mac os"), strings.Contains(os, "darwin"):
		return "darwin"
	case strings.Contains(os, "windows"):
		return "windows"
	default:
		return "linux"
	}
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

// linkRec is a recorded symlink read: its target on success, or a recorded error
// (absent / unreadable) so replay reproduces the live os.Readlink outcome rather
// than falling through to the replaying machine's own filesystem.
type linkRec struct {
	target     string
	notExist   bool
	permission bool
	errText    string
}

// statRec is a recorded os.Stat: the metadata on success, or a recorded error
// (absent / unreadable) so an existence/size/mode gate replays the live outcome
// instead of probing the replaying machine's own filesystem.
type statRec struct {
	meta       FileMeta
	notExist   bool
	permission bool
	errText    string
}

// statfsRec is a recorded syscall.Statfs: the stats on success, or a recorded
// error (absent / unreadable) so a filesystem-usage probe replays the live
// outcome instead of stat-ing the replaying machine's own filesystem.
type statfsRec struct {
	info       StatfsInfo
	notExist   bool
	permission bool
	errText    string
}

// Bundle is the in-memory, persistable record of every system input touched
// during a capture. Safe for concurrent use — collectors run in parallel.
type Bundle struct {
	Manifest Manifest

	mu      sync.RWMutex
	files   map[string]fileRec
	globs   map[string][]string
	dirs    map[string][]string
	cmds    map[string]cmdRec
	links   map[string]linkRec
	stats   map[string]statRec
	statfss map[string]statfsRec
}

// NewBundle returns an empty bundle stamped with the current format version.
func NewBundle() *Bundle {
	return &Bundle{
		Manifest: Manifest{Format: FormatVersion},
		files:    map[string]fileRec{},
		globs:    map[string][]string{},
		dirs:     map[string][]string{},
		cmds:     map[string]cmdRec{},
		links:    map[string]linkRec{},
		stats:    map[string]statRec{},
		statfss:  map[string]statfsRec{},
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

// PutDir seeds dir's entry names for Replay.ReadDir, mirroring PutFile — lets a
// test build a fixture bundle for a collector that lists a directory (e.g. cron
// spool dirs, /sys/class/... globs) without touching the real filesystem.
func (b *Bundle) PutDir(dir string, names []string) { b.putDir(dir, names) }

// PutGlob seeds pattern's matches for Replay.Glob, mirroring PutFile.
func (b *Bundle) PutGlob(pattern string, matches []string) { b.putGlob(pattern, matches) }

// PutStat seeds path's metadata for Replay.Stat, mirroring PutFile — lets a
// test exercise a collector's fileExists()/statFile() existence or mtime gate
// without touching the real filesystem.
func (b *Bundle) PutStat(path string, meta FileMeta) { b.putStat(path, meta, nil) }

// PutCmd seeds the successful (spawn-succeeded) output of name+args for
// Replay.Run, mirroring PutFile — lets a test exercise a collector's runCmd-
// based parser (external tool output) without actually running the tool.
// Use PutCmdNotFound for the "binary not installed" case instead.
func (b *Bundle) PutCmd(name string, args []string, stdout string, exitCode int) {
	b.putCmd(name, args, Result{Stdout: []byte(stdout), ExitCode: exitCode}, nil)
}

// PutCmdNotFound seeds a spawn failure (tool not installed) for Replay.Run.
func (b *Bundle) PutCmdNotFound(name string, args []string) {
	b.putCmd(name, args, Result{}, &exec.Error{Name: name, Err: exec.ErrNotFound})
}

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

func (b *Bundle) putLink(path, target string, err error) {
	rec := linkRec{}
	switch {
	case err == nil:
		rec.target = target
	case errors.Is(err, fs.ErrNotExist):
		rec.notExist = true
	case errors.Is(err, fs.ErrPermission):
		rec.permission = true
		rec.errText = err.Error()
	default:
		rec.errText = err.Error()
	}
	b.mu.Lock()
	b.links[cleanPath(path)] = rec
	b.mu.Unlock()
}

func (b *Bundle) getLink(path string) (linkRec, bool) {
	b.mu.RLock()
	rec, ok := b.links[cleanPath(path)]
	b.mu.RUnlock()
	return rec, ok
}

func (b *Bundle) putStat(path string, meta FileMeta, err error) {
	rec := statRec{}
	switch {
	case err == nil:
		rec.meta = meta
	case errors.Is(err, fs.ErrNotExist):
		rec.notExist = true
	case errors.Is(err, fs.ErrPermission):
		rec.permission = true
		rec.errText = err.Error()
	default:
		rec.errText = err.Error()
	}
	b.mu.Lock()
	b.stats[cleanPath(path)] = rec
	b.mu.Unlock()
}

func (b *Bundle) getStat(path string) (statRec, bool) {
	b.mu.RLock()
	rec, ok := b.stats[cleanPath(path)]
	b.mu.RUnlock()
	return rec, ok
}

func (b *Bundle) putStatfs(path string, info StatfsInfo, err error) {
	rec := statfsRec{}
	switch {
	case err == nil:
		rec.info = info
	case errors.Is(err, fs.ErrNotExist):
		rec.notExist = true
	case errors.Is(err, fs.ErrPermission):
		rec.permission = true
		rec.errText = err.Error()
	default:
		rec.errText = err.Error()
	}
	b.mu.Lock()
	b.statfss[cleanPath(path)] = rec
	b.mu.Unlock()
}

func (b *Bundle) getStatfs(path string) (statfsRec, bool) {
	b.mu.RLock()
	rec, ok := b.statfss[cleanPath(path)]
	b.mu.RUnlock()
	return rec, ok
}
