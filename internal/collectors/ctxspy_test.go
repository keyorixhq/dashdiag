//go:build linux

package collectors

import (
	"context"
	"os"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// ctxSpyExecSource is a test Source that records the context passed to Run
// (the exec.CommandContext path) while delegating everything else (Stat,
// ReadFile, ...) to a real source.Live — so a helper under test can gate on a
// real file's existence but the actual subprocess exec is faked out and its
// context captured. This exists to catch collector helpers that silently
// call runCmd(context.Background(), ...) instead of threading through the
// caller's ctx: a bug that decouples the subprocess from both the
// collector's Timeout() and the runner's overall deadline, letting a single
// hung external tool blow the whole health-check budget (or leak a
// goroutine/child process past it).
//
// statOverrides lets a test claim a path "exists" (or definitely does not)
// without touching the real filesystem (e.g. faking /dev/nitro_enclaves
// being present on a machine that obviously has no such device).
type ctxSpyExecSource struct {
	source.Live
	gotCtx        context.Context
	stdout        string
	statOverrides map[string]bool // path -> exists
}

func (s *ctxSpyExecSource) Stat(path string) (source.FileMeta, error) {
	if exists, ok := s.statOverrides[path]; ok {
		if exists {
			return source.FileMeta{}, nil
		}
		return source.FileMeta{}, os.ErrNotExist
	}
	return s.Live.Stat(path)
}

func (s *ctxSpyExecSource) Run(ctx context.Context, _ string, _ ...string) (source.Result, error) {
	s.gotCtx = ctx
	return source.Result{Stdout: []byte(s.stdout)}, nil
}

// ctxMarkerKey / ctxMarkerValue tag a context so a test can tell "the real
// caller-supplied context reached runCmd" apart from "a fresh
// context.Background() was substituted instead" — a plain ctx.Err()/Done()
// check can't distinguish those, since neither is cancelled in the common
// (bug or no bug) case.
type ctxMarkerKeyType struct{}

var ctxMarkerKey = ctxMarkerKeyType{}

const ctxMarkerValue = "regression-test-marker"

// withCtxMarker returns a context a test can pass into the function under
// test; markedCtx reports whether a context handed to the spy Source is that
// exact marked context (propagated) as opposed to an unrelated one (e.g.
// context.Background(), meaning the caller's ctx was dropped).
func withCtxMarker(parent context.Context) context.Context {
	return context.WithValue(parent, ctxMarkerKey, ctxMarkerValue)
}

func markedCtx(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(ctxMarkerKey).(string)
	return v == ctxMarkerValue
}
