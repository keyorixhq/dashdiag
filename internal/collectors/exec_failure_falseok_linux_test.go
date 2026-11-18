//go:build linux

package collectors_test

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// EXF1 — false-OK at the EXEC layer.
//
// This harness injects the standard exec-failure catalog (empty/exit-0, warning-
// only, non-zero+partial, exit 100/127/126, permission denied, lock, timeout,
// truncated-mid-line, foreign locale, very large, control chars) into the fake
// SOURCE seam (collectors.SetSource) for an AVAILABLE subsystem, runs the REAL
// collector AND the REAL analysis pipeline (analysis.ApplyThresholds), and asserts
// the ORACLE: when the data the verdict depends on was NOT obtained, the check
// must not render a silent all-clear (an empty insight set) — it must disclose
// Unverified or a finding. OK in this product is the ABSENCE of an insight, so an
// empty insight set from an available-but-unmeasured subsystem IS the false-OK.
//
// Resource meters: none enabled. Every case is pure in-memory model construction
// plus a fixed set of analysis calls — no goroutines, no real filesystem, no sleep,
// no network, allocation bounded by the injected payload (≤1 MiB huge-output mode).
// The shared resource helper (internal/testutil/resource) governs memory/CPU/FD/
// sleep; none of those are exercised here, so wiring it in would meter nothing.

// ─────────────────────────── fake source ────────────────────────────────────

// execFailSource is a fully controlled source.Source. File/stat/cached lookups are
// served from seeded maps (to pass a collector's availability gate); EVERY external
// command (Run) returns the single injected (Result, error), modelling "the tool
// query for this subsystem failed in mode X".
type execFailSource struct {
	files  map[string][]byte
	stats  map[string]source.FileMeta
	cached map[string][]byte
	runRes source.Result
	runErr error
}

func (s execFailSource) ReadFile(path string) ([]byte, error) {
	if b, ok := s.files[path]; ok {
		return b, nil
	}
	return nil, fs.ErrNotExist
}
func (execFailSource) Glob(string) ([]string, error)    { return nil, nil }
func (execFailSource) ReadDir(string) ([]string, error) { return nil, fs.ErrNotExist }
func (execFailSource) Readlink(string) (string, error)  { return "", fs.ErrNotExist }
func (s execFailSource) Stat(path string) (source.FileMeta, error) {
	if m, ok := s.stats[path]; ok {
		return m, nil
	}
	return source.FileMeta{}, fs.ErrNotExist
}
func (execFailSource) Statfs(string) (source.StatfsInfo, error) {
	return source.StatfsInfo{}, fs.ErrNotExist
}
func (s execFailSource) Cached(key string, _ func() ([]byte, error)) ([]byte, error) {
	if b, ok := s.cached[key]; ok {
		return b, nil
	}
	return nil, errors.New("not found")
}
func (s execFailSource) Run(context.Context, string, ...string) (source.Result, error) {
	return s.runRes, s.runErr
}

// ─────────────────────────── failure catalog ────────────────────────────────

type execFailMode struct {
	name  string
	build func(valid string) (source.Result, error)
}

func half(s string) string {
	if len(s) < 2 {
		return s
	}
	return s[:len(s)/2] // cut mid-line on purpose
}

// execFailModes is the catalog. Every mode models the data NOT being obtained:
// stdout is empty, an error, or non-answer text — never a valid state token.
var execFailModes = []execFailMode{
	{"empty-exit0", func(string) (source.Result, error) {
		return source.Result{ExitCode: 0}, nil
	}},
	{"warning-only-exit0", func(string) (source.Result, error) {
		return source.Result{ExitCode: 0, Stdout: []byte("Warning: configuration option deprecated\n")}, nil
	}},
	{"nonzero-partial", func(valid string) (source.Result, error) {
		return source.Result{ExitCode: 1, Stdout: []byte(half(valid))}, nil
	}},
	{"exit-100", func(string) (source.Result, error) {
		return source.Result{ExitCode: 100}, nil
	}},
	{"exit-127", func(string) (source.Result, error) {
		return source.Result{ExitCode: 127}, nil
	}},
	{"exit-126", func(string) (source.Result, error) {
		return source.Result{ExitCode: 126}, nil
	}},
	{"perm-denied-stderr", func(string) (source.Result, error) {
		return source.Result{ExitCode: 1, Stderr: []byte("bash: permission denied\n")}, nil
	}},
	{"lock-error", func(string) (source.Result, error) {
		return source.Result{ExitCode: 7, Stderr: []byte("System management is locked by the application with pid 4242\n")}, nil
	}},
	{"timeout", func(string) (source.Result, error) {
		return source.Result{}, context.DeadlineExceeded
	}},
	{"truncated-midline", func(valid string) (source.Result, error) {
		return source.Result{ExitCode: 0, Stdout: []byte(half(valid))}, nil
	}},
	{"foreign-locale", func(string) (source.Result, error) {
		// production forces LC_ALL=C; inject a translated line to confirm no parser
		// mistakes it for a valid English token.
		return source.Result{ExitCode: 0, Stdout: []byte("habilitado\n")}, nil
	}},
	{"huge-output", func(string) (source.Result, error) {
		return source.Result{ExitCode: 0, Stdout: []byte(strings.Repeat("x", 1<<20))}, nil
	}},
	{"control-chars", func(string) (source.Result, error) {
		return source.Result{ExitCode: 0, Stdout: []byte("\x00\x01\x02\x07\x1b[2J\x00\n")}, nil
	}},
}

// ─────────────────────────── cases under test ───────────────────────────────

// execFailCase is one AVAILABLE subsystem whose verdict is exec-derived. collect
// swaps in the fake source, runs the real collector, and returns the runner.Result
// that analysis.ApplyThresholds then turns into insights.
type execFailCase struct {
	name  string
	valid string // a realistic valid stdout, feeds the partial/truncated modes
	src   func(res source.Result, err error) execFailSource
	// collect runs the real collector against the active source, returning a
	// runner.Result whose Data is the raw model.
	collect func(t *testing.T) runner.Result
}

var execFailCases = []execFailCase{
	{
		name:  "Kdump/systemctl",
		valid: "enabled\n",
		src: func(res source.Result, err error) execFailSource {
			return execFailSource{
				stats:  map[string]source.FileMeta{"/usr/lib/systemd/system/kdump.service": {}},
				runRes: res, runErr: err,
			}
		},
		collect: func(t *testing.T) runner.Result {
			raw, err := collectors.NewKdumpCollector(platform.ContainerContext{}).Collect(context.Background())
			if err != nil {
				t.Fatalf("Kdump collect: %v", err)
			}
			return runner.Result{Name: "Kdump", Data: raw}
		},
	},
	{
		name:  "Tuned/systemctl+tuned-adm",
		valid: "active\n",
		src: func(res source.Result, err error) execFailSource {
			return execFailSource{
				cached: map[string][]byte{"lookpath/tuned-adm": []byte("/usr/bin/tuned-adm")},
				runRes: res, runErr: err,
			}
		},
		collect: func(t *testing.T) runner.Result {
			raw, err := collectors.NewTunedCollector().Collect(context.Background())
			if err != nil {
				t.Fatalf("Tuned collect: %v", err)
			}
			return runner.Result{Name: "Tuned", Data: raw}
		},
	},
	{
		name:  "Ceph/health+osd",
		valid: `{"status":"HEALTH_OK","checks":{}}`,
		src: func(res source.Result, err error) execFailSource {
			return execFailSource{
				stats:  map[string]source.FileMeta{"/etc/ceph/ceph.conf": {}},
				runRes: res, runErr: err,
			}
		},
		collect: func(t *testing.T) runner.Result {
			raw, err := (&collectors.CephCollector{}).Collect(context.Background())
			if err != nil {
				t.Fatalf("Ceph collect: %v", err)
			}
			return runner.Result{Name: "Ceph", Data: raw}
		},
	},
}

func analyze(r runner.Result) []models.Insight {
	env := platform.CloudEnvironment(0)
	return analysis.ApplyThresholds([]runner.Result{r}, analysis.DefaultThresholds(env), env, platform.ContainerContext{})
}

// runCase injects (res,err) for a case, runs collect+analysis, restores the source.
func runCase(t *testing.T, c execFailCase, res source.Result, err error) []models.Insight {
	t.Helper()
	prev := collectors.SetSource(c.src(res, err))
	defer collectors.SetSource(prev)
	return analyze(c.collect(t))
}

// isSilentOK reports the false-OK shape: no insight at all (OK == absence of an
// insight), i.e. an available-but-unmeasured subsystem rendered an all-clear.
func isSilentOK(ins []models.Insight) bool { return len(ins) == 0 }

// TestExecFailureMatrix is the exploratory driver: it prints, for every
// (case, mode), whether the subsystem silently passed. Used to build the EXF1
// matrix empirically; the committed oracle (FuzzExecFailureFalseOK) asserts the
// sound property directly.
func TestExecFailureMatrix(t *testing.T) {
	for _, c := range execFailCases {
		for _, m := range execFailModes {
			res, err := m.build(c.valid)
			ins := runCase(t, c, res, err)
			levels := make([]string, 0, len(ins))
			unv := false
			for _, i := range ins {
				levels = append(levels, i.Level)
				if i.Unverified {
					unv = true
				}
			}
			verdict := "DISCLOSED"
			if isSilentOK(ins) {
				verdict = "SILENT-OK"
			}
			t.Logf("MATRIX %-26s %-20s insights=%d levels=%v unverified=%v -> %s",
				c.name, m.name, len(ins), levels, unv, verdict)
		}
	}
}

// FuzzExecFailureFalseOK is the committed EXF1 oracle. It drives a fuzzer-chosen
// external-command outcome (exit code, stdout, stderr, spawn/timeout error) into
// the source seam for an AVAILABLE subsystem, runs the real collector + the real
// analysis pipeline, and asserts the SOUND false-OK property:
//
//	when NO usable stdout was obtained (stdout empty after trimming), the check
//	MUST NOT render a silent all-clear — it must disclose Unverified or a finding.
//
// It never panics on any outcome. The property is asserted only on empty-stdout
// (the unambiguous "data not obtained" case), which the matrix confirms every
// subsystem here already satisfies — so this guard pins that behavior against
// regression (the AC1 class: an exec failure silently read as a clean verdict).
func FuzzExecFailureFalseOK(f *testing.F) {
	f.Add(0, 0, []byte(""), []byte(""), false)
	f.Add(1, 1, []byte(""), []byte("permission denied"), false)
	f.Add(2, 7, []byte(""), []byte("locked by pid 42"), false)
	f.Add(0, 0, []byte(""), []byte(""), true)
	f.Add(1, 100, []byte("partial"), []byte(""), false)
	f.Add(2, 0, []byte(`{"status":"HEALTH_OK"`), []byte(""), false)
	f.Add(0, 0, []byte("enabled\n"), []byte(""), false)

	f.Fuzz(func(t *testing.T, caseSel, exitCode int, stdout, stderr []byte, useErr bool) {
		if caseSel < 0 {
			caseSel = -caseSel
		}
		c := execFailCases[caseSel%len(execFailCases)]
		res := source.Result{ExitCode: exitCode, Stdout: stdout, Stderr: stderr}
		var err error
		if useErr {
			err = context.DeadlineExceeded
		}
		ins := runCase(t, c, res, err) // must not panic on any outcome

		// Sound oracle: with no usable stdout, the verdict data was not obtained,
		// so an available subsystem must not be silent.
		if strings.TrimSpace(string(stdout)) == "" && isSilentOK(ins) {
			t.Fatalf("FALSE-OK: %s rendered a silent all-clear with no stdout "+
				"(exit=%d err=%v stderr=%q) — an available-but-unmeasured subsystem must disclose Unverified or a finding",
				c.name, exitCode, err, stderr)
		}
	})
}
