package collectors

// fsaccess.go — file/sysfs read helpers routed through the active source.
//
// Collectors that read /sys, /proc, or other files go through these (not
// os.ReadFile / filepath.Glob / os.Open / os.ReadDir directly) so
// `dsd capture --raw` records exactly what they read and `dsd replay` can
// serve it back. No build tag — helpers are used by Linux and darwin collectors.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// lookPath reports the resolved path of a tool on $PATH, routed through the active
// source so a "is tool X installed" gate replays from the capture instead of
// reading the replaying machine's $PATH. Drop-in for exec.LookPath: a tool absent
// at capture replays as an error (gate false); a tool present replays its recorded
// path. On a recording gap (older bundle) it returns an error (don't claim a tool
// we never observed). Keyed by tool name.
func lookPath(name string) (string, error) {
	data, err := curSource().Cached("lookpath/"+name, func() ([]byte, error) {
		p, e := exec.LookPath(name)
		if e != nil {
			return nil, e
		}
		return []byte(p), nil
	})
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// getenv returns the value of environment variable name, routed through the
// active source so a verdict-affecting env read (e.g. the SteamOS Game-Mode
// session-type signal, XDG_SESSION_DESKTOP) replays from the CAPTURED host's
// value instead of the replaying machine's own environment — the same "captured
// host, not the replaying box" guarantee lookPath gives $PATH lookups. Drop-in
// for os.Getenv: an unset var at capture (or a recording gap in an older bundle)
// replays as "", matching os.Getenv's own unset-vs-empty conflation. Keyed by
// var name. Not for uid/gid/euid-style live-privilege reads (those are
// legitimately live-only — see collectSocketPermReason in docker.go).
func getenv(name string) string {
	data, err := curSource().Cached("env/"+name, func() ([]byte, error) {
		return []byte(os.Getenv(name)), nil
	})
	if err != nil {
		return ""
	}
	return string(data)
}

// cachedJSON makes a computed value (e.g. a gopsutil call that reads /proc via its
// own API, bypassing the file wrappers) hermetic under capture/replay. compute is
// run on a live or capture pass and its result recorded as JSON; on `dsd replay`
// the recorded JSON is decoded into out and compute is NEVER called — so no live
// probe runs. key must be stable and unique. out must be a non-nil pointer.
func cachedJSON(key string, compute func() (any, error), out any) error {
	data, err := curSource().Cached(key, func() ([]byte, error) {
		v, e := compute()
		if e != nil {
			return nil, e
		}
		return json.Marshal(v)
	})
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

// maxCappedFileBytes bounds how many bytes readFile/openFile return from a
// single file, mirroring the io.LimitReader cap netaccess_linux.go's
// httpGetLive and cloudmeta_linux.go's IMDS fetch already apply to network
// reads (guard_name in the resource-exhaustion review: "io.LimitReader
// equivalent... absent here"). This caps what's RETAINED and handed to the
// parser — still closes the "unbounded memory downstream" attack path (a huge
// /var/log/syslog fallback scan, or a crafted oversized bundle entry). Set
// generous enough for any legitimate /proc, /sys, or log-tail read.
//
// This does NOT by itself bound the one-time read cost below — see
// maxSafeReadBytes / statSizeHint for the before-read half of the guard.
const maxCappedFileBytes = 16 << 20 // 16MiB

// maxSafeReadBytes is the size threshold beyond which readFile/openFile
// refuse to attempt a full read at all (internal-collectors-18-02/19-03): a
// pathologically huge file (an attacker-flooded /var/log/secure, or a
// malicious `dsd replay` bundle entry claiming an oversized payload) must
// never be fully materialized into memory just to be truncated afterwards.
// Set to 10x maxCappedFileBytes — far beyond any legitimate /proc, /sys, or
// log file, so it only fires for a genuinely pathological/adversarial read.
//
// The Source interface (internal/source) has no seek/range-read primitive —
// ReadFile always returns the full []byte — so a true tail-seek isn't
// achievable at this layer without changing that abstraction. statSizeHint
// gives a best-effort size probe via the existing Stat() call instead: when
// it reports a size over this threshold, the read is skipped entirely
// (errFileTooLarge) rather than materializing it; when Stat is unavailable
// (including a replay bundle recorded before this probe existed — Stat and
// ReadFile are independently keyed, see internal/source/bundle.go) the
// helpers fall back to the prior full-read-then-truncate behaviour, so old
// bundles keep replaying exactly as before.
const maxSafeReadBytes = maxCappedFileBytes * 10 // 160MiB

// errFileTooLarge is returned by readFile/openFile when statSizeHint reports
// a path far beyond any legitimate size for what these helpers read — see
// maxSafeReadBytes. Callers already branch on "read failed" (permission
// denied, not found, etc.) via the same err!=nil / os.IsPermission checks;
// this is deliberately just another such error so it flows through those
// existing "couldn't audit this" fallback paths without each call site
// needing special-case handling.
var errFileTooLarge = errors.New("fsaccess: file too large to safely read")

// statSizeHint returns the size Stat reports for path, or -1 when Stat itself
// is unavailable — any error, including source.ErrNotRecorded for a replay
// bundle that never captured a Stat for this path (expected for bundles
// captured before this probe existed, since Recorder only records a Stat
// when a collector explicitly calls one — see internal/source/recorder.go).
// -1 means "unknown", not "empty": callers must treat it as "proceed with
// the existing full-read+cap behaviour", never as a zero-size fast path.
//
// readFile/openFile are the package's shared low-level read path — dozens of
// collectors' tests build a minimal fake source.Source (embedding the
// interface and overriding only ReadFile) to exercise a single branch without
// wiring a full fixture, deliberately leaving every other method — including
// Stat — nil so an unexpected call panics and flags itself. Adding a
// mandatory Stat() call here must not turn every one of those pre-existing
// test doubles into a panic; the recover mirrors the same defensive posture
// internal/drilldown/drilldown.go already uses around a dependency that may
// not implement what's expected (dispatchLive's recover-to-nil). A genuine
// live/replay Source always implements Stat; only a deliberately-partial test
// double hits this path.
func statSizeHint(path string) (size int64) {
	defer func() {
		if recover() != nil {
			size = -1
		}
	}()
	meta, err := curSource().Stat(path)
	if err != nil {
		return -1
	}
	return meta.Size
}

// maxCappedDirEntries bounds how many names glob/readDirNames return, for the
// same reason: an adversarial replay bundle (or a pathological live glob/dir)
// must not be able to force allocation of millions of entries.
const maxCappedDirEntries = 200_000

// capFileBytes truncates data to maxCappedFileBytes, KEEPING THE TAIL. Every
// current caller of readFile/openFile that reads an append-only, ever-growing
// file (e.g. cron_linux.go's syslog-style fallback scan) cares about the most
// RECENT bytes; truncating from the front would silently discard exactly the
// data being asked for.
func capFileBytes(data []byte) []byte {
	if len(data) <= maxCappedFileBytes {
		return data
	}
	return data[len(data)-maxCappedFileBytes:]
}

// capDirEntries truncates names to maxCappedDirEntries.
func capDirEntries(names []string) []string {
	if len(names) <= maxCappedDirEntries {
		return names
	}
	return names[:maxCappedDirEntries]
}

// readFile returns the contents of path via the active source, capped at
// maxCappedFileBytes (tail-preserving — see capFileBytes). A best-effort Stat
// probe runs first (statSizeHint); a path reported far beyond any legitimate
// size (maxSafeReadBytes) is never read at all — see errFileTooLarge.
func readFile(path string) ([]byte, error) {
	if sz := statSizeHint(path); sz > maxSafeReadBytes {
		return nil, errFileTooLarge
	}
	data, err := curSource().ReadFile(path)
	if err != nil {
		return nil, err
	}
	return capFileBytes(data), nil
}

// glob expands a shell pattern (filepath.Glob semantics) via the active
// source, capped at maxCappedDirEntries matches.
func glob(pattern string) ([]string, error) {
	m, err := curSource().Glob(pattern)
	if err != nil {
		return nil, err
	}
	return capDirEntries(m), nil
}

// openFile reads path via the active source and returns an io.ReadCloser,
// capped at maxCappedFileBytes (tail-preserving — see capFileBytes). Same
// before-read size probe as readFile — see statSizeHint / errFileTooLarge.
// Use this as a drop-in for os.Open where the caller passes the result to a
// parser that expects an io.Reader / io.ReadCloser.
func openFile(path string) (io.ReadCloser, error) {
	if sz := statSizeHint(path); sz > maxSafeReadBytes {
		return nil, errFileTooLarge
	}
	data, err := curSource().ReadFile(path)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(capFileBytes(data))), nil
}

// readDirNames returns the sorted entry names of dir via the active source,
// capped at maxCappedDirEntries. Use for callers that only need names (no
// IsDir / Info needed).
func readDirNames(dir string) ([]string, error) {
	names, err := curSource().ReadDir(dir)
	if err != nil {
		return nil, err
	}
	return capDirEntries(names), nil
}

// readLink returns the target of the symlink at path via the active source, so
// capture/replay reproduces it instead of os.Readlink hitting the live machine.
func readLink(path string) (string, error) { return curSource().Readlink(path) }

// statFile returns metadata for path via the active source (os.Stat semantics),
// so an existence / size / mode / is-dir gate replays from the capture instead of
// os.Stat hitting the replaying machine. Use this as a drop-in for os.Stat.
func statFile(path string) (source.FileMeta, error) { return curSource().Stat(path) }

// statFs returns filesystem statistics for path via the active source
// (syscall.Statfs semantics), so a disk-usage / mount-liveness probe replays from
// the capture instead of stat-ing the replaying machine's filesystem. Use as a
// drop-in for `syscall.Statfs(path, &st)` — the returned struct's fields mirror
// the syscall.Statfs_t fields collectors read (Blocks, Bsize, Bfree, …).
func statFs(path string) (source.StatfsInfo, error) { return curSource().Statfs(path) }

// fileExists reports whether path exists, routed through the active source. Use
// this as a drop-in for the common `if _, err := os.Stat(p); err == nil` gate so
// the existence check is recorded and replayed rather than probing the live
// machine. A permission error counts as "exists" (present but unreadable), which
// matches os.Stat returning a non-os.IsNotExist error for that case.
func fileExists(path string) bool {
	_, err := statFile(path)
	if err == nil {
		return true
	}
	return errors.Is(err, fs.ErrPermission)
}

// readDirEntries returns a synthetic []fs.DirEntry for dir via the active
// source. IsDir() is derived by probing whether dir/name has children in the
// source — sufficient for the filter patterns used in collectors (skip dirs,
// include only files, walk sub-dirs by name).
func readDirEntries(dir string) ([]fs.DirEntry, error) {
	names, err := curSource().ReadDir(dir)
	if err != nil {
		return nil, err
	}
	entries := make([]fs.DirEntry, len(names))
	for i, name := range names {
		entries[i] = fakeDirEntry{
			name:  name,
			isDir: probeIsDir(filepath.Join(dir, name)),
		}
	}
	return entries, nil
}

// probeIsDir returns true if path appears to be a directory in the active
// source: ReadDir succeeds (even if empty — an empty dir is still a dir).
func probeIsDir(path string) bool {
	_, err := curSource().ReadDir(path)
	return err == nil
}

// fakeDirEntry satisfies fs.DirEntry with name and isDir only.
type fakeDirEntry struct {
	name  string
	isDir bool
}

func (f fakeDirEntry) Name() string               { return f.name }
func (f fakeDirEntry) IsDir() bool                { return f.isDir }
func (f fakeDirEntry) Type() fs.FileMode          { return 0 }
func (f fakeDirEntry) Info() (fs.FileInfo, error) { return fakeFileInfo(f), nil }

type fakeFileInfo struct {
	name  string
	isDir bool
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() fs.FileMode  { return 0o644 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.isDir }
func (f fakeFileInfo) Sys() any           { return nil }

// ReadFileViaSource, GlobViaSource, and ReadlinkViaSource are exported for
// callers outside the collectors package (cmd/, internal/analysis) that need
// source-routed reads without a collector context — so their sysfs reads are
// captured by `dsd capture --raw` and served by `dsd replay` instead of hitting
// the live machine.
func ReadFileViaSource(path string) ([]byte, error)  { return curSource().ReadFile(path) }
func GlobViaSource(pattern string) ([]string, error) { return curSource().Glob(pattern) }
func ReadlinkViaSource(path string) (string, error)  { return curSource().Readlink(path) }

// NowViaSource returns the wall-clock time routed through the active source, so
// it is captured by `dsd capture --raw` and replayed faithfully: under replay it
// returns the CAPTURE time, not the replaying machine's clock. Any "age since
// event" math (e.g. a log line's age) is then relative to the captured host's
// moment — both faithful AND byte-stable across repeated replays of one bundle.
// Without this, age was computed against the live replay clock, so two replays a
// second apart could differ (e.g. age_min 2 vs 3) — a hermeticity regression the
// replay-hermetic CI guard flagged. The Recorder records the value under a fixed
// key; every NowViaSource call in one replay returns that same recorded instant.
// Falls back to the live clock on any cache/parse error (never blocks a live run).
func NowViaSource() time.Time {
	b, err := curSource().Cached("__wallclock_now__", func() ([]byte, error) {
		return []byte(time.Now().UTC().Format(time.RFC3339Nano)), nil
	})
	if err != nil {
		return time.Now()
	}
	t, perr := time.Parse(time.RFC3339Nano, string(b))
	if perr != nil {
		return time.Now()
	}
	return t
}
