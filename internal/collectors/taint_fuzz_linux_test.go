//go:build linux && taintoverlay

package collectors

// Input-to-sink taint harness for the collectors (see internal/fuzzutil/taint).
//
// Collectors read host data (files, directory listings, command output) that an
// unprivileged local actor can shape (unit names, container names, mount points,
// process names, ...). The risk class is second-order use of that data: a name
// read from one file becoming a path or a command argument in the next call.
// The harness wraps a real captured bundle (fixtures/replay-fidelity) in a
// Source whose every returned token may carry the marker, and reports where a
// marker-bearing value is later passed back into Source.ReadFile/Stat/Glob/
// ReadDir/Readlink/Statfs (path) or Source.Run (command) via taint.Sink.
//
// Contract allow-list, fixed before the first run (see PREREG in fuzz-corpus):
// a host-derived name as a data argument of the command that inspects it is
// allowed and recorded (a leading-dash form without a preceding "--" is not);
// an enumerated name used as a component of an absolute path without "..", for
// example /proc/<pid>/status after listing /proc, is the documented purpose of
// enumeration and is ALLOWED but recorded (reported via Flows()). Everything else is
// unexpected: a marker at the start of a path, a path with "..", any marker in a
// command name or argument.
//
// Run: go test -tags taintoverlay -overlay <taintoverlay dir>/overlay.json \
//        -vet=off -run '^$' -fuzz FuzzTaintCollectors ./internal/collectors

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/fuzzutil/taint"
	"github.com/keyorixhq/dashdiag/internal/source"
)

type taintSource struct {
	inner source.Source
	salt  uint8 // which tokens are tainted
	mode  uint8 // marker placement
}

func isTok(r byte) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.'
}

// taintText replaces some whitespace/punctuation-delimited tokens (length >= 3)
// by marker-bearing versions of themselves.
func (s taintSource) taintText(b []byte) []byte {
	var out []byte
	n := 0
	for i := 0; i < len(b); {
		if !isTok(b[i]) {
			out = append(out, b[i])
			i++
			continue
		}
		j := i
		for j < len(b) && isTok(b[j]) {
			j++
		}
		tok := string(b[i:j])
		n++
		if len(tok) >= 3 && (n+int(s.salt))%7 == 0 {
			switch s.mode % 4 {
			case 0:
				tok = taint.Marker()
			case 1:
				tok = taint.Marker() + tok
			case 2:
				tok += taint.Marker()
			default:
				tok = "-" + taint.Marker() + tok // option-injection form
			}
		}
		out = append(out, tok...)
		i = j
	}
	return out
}

func (s taintSource) taintStr(x string) string { return string(s.taintText([]byte(x))) }

func (s taintSource) ReadFile(p string) ([]byte, error) {
	taint.Sink(taint.Path, "source.ReadFile", p)
	b, err := s.inner.ReadFile(p)
	return s.taintText(b), err
}
func (s taintSource) Glob(pat string) ([]string, error) {
	taint.Sink(taint.Path, "source.Glob", pat)
	m, err := s.inner.Glob(pat)
	for i := range m {
		m[i] = filepath.Join(filepath.Dir(m[i]), s.taintStr(filepath.Base(m[i])))
	}
	return m, err
}
func (s taintSource) ReadDir(d string) ([]string, error) {
	taint.Sink(taint.Path, "source.ReadDir", d)
	m, err := s.inner.ReadDir(d)
	for i := range m {
		m[i] = s.taintStr(m[i])
	}
	return m, err
}
func (s taintSource) Readlink(p string) (string, error) {
	taint.Sink(taint.Path, "source.Readlink", p)
	t, err := s.inner.Readlink(p)
	return s.taintStr(t), err
}
func (s taintSource) Stat(p string) (source.FileMeta, error) {
	taint.Sink(taint.Path, "source.Stat", p)
	return s.inner.Stat(p)
}
func (s taintSource) Statfs(p string) (source.StatfsInfo, error) {
	taint.Sink(taint.Path, "source.Statfs", p)
	return s.inner.Statfs(p)
}
func (s taintSource) Cached(key string, produce func() ([]byte, error)) ([]byte, error) {
	b, err := s.inner.Cached(key, produce)
	return s.taintText(b), err
}
func (s taintSource) Run(ctx context.Context, name string, args ...string) (source.Result, error) {
	taint.Sink(taint.Command, "source.Run.name", name)
	dd := false
	for _, a := range args {
		switch {
		case a == "--":
			dd = true
		case strings.HasPrefix(a, "-") && !dd:
			// a leading '-' with the marker inside is an option-injection form;
			// plain constant options (no marker) are ignored by the oracle.
			taint.Sink(taint.Command, "source.Run.optionArg", a)
		default:
			taint.Sink(taint.Command, "source.Run.dataArg", a)
		}
	}
	r, err := s.inner.Run(ctx, name, args...)
	r.Stdout, r.Stderr = s.taintText(r.Stdout), s.taintText(r.Stderr)
	return r, err
}

func sortedCtorNames() []string {
	var ns []string
	for n := range taintCollectorCtors {
		ns = append(ns, n)
	}
	sort.Strings(ns)
	return ns
}

func FuzzTaintCollectors(f *testing.F) {
	bundle, err := source.LoadTarball("../../fixtures/replay-fidelity/debian13-vmware-nonroot.tar.gz")
	if err != nil {
		f.Fatal(err)
	}
	names := sortedCtorNames()
	f.Add(uint16(0), uint8(0), uint8(0))
	taint.Allow(taint.Rule{
		Class: taint.Command, Op: "source.Run.dataArg",
		Why: "host-derived name passed as a data argument of the tool that inspects it (documented purpose); option-injection forms are not allowed",
	})
	taint.Allow(taint.Rule{
		Class: taint.Path,
		Why:   "enumerated name used as a component of an absolute path without '..' (documented purpose of enumeration)",
		Func: func(v taint.Violation) bool {
			p := v.Value
			return strings.HasPrefix(p, "/") && !strings.Contains(p, "..") && !strings.HasPrefix(p, "/"+taint.Marker())
		},
	})
	// POST-HOC: after a candidate has been recorded and classified, its frame can
	// be allow-listed through TAINT_POSTHOC_FRAMES (comma-separated function-name
	// substrings) so the run continues to look for further, different flows.
	for _, fr := range strings.Split(os.Getenv("TAINT_POSTHOC_FRAMES"), ",") {
		if fr != "" {
			taint.Allow(taint.Rule{Class: taint.Command, Frame: fr, Why: "POST-HOC (classified candidate): " + fr})
			taint.Allow(taint.Rule{Class: taint.Path, Frame: fr, Why: "POST-HOC (classified candidate): " + fr})
		}
	}
	f.Fuzz(func(t *testing.T, which uint16, salt, mode uint8) {
		taint.Reset()
		defer taint.Check(t.Fatalf)
		name := names[int(which)%len(names)]
		prev := SetSource(taintSource{inner: source.NewReplay(bundle), salt: salt, mode: mode})
		defer SetSource(prev)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c := taintCollectorCtors[name]()
		func() {
			defer func() { _ = recover() }() // panics are other fuzz targets' business
			_, _ = c.Collect(ctx)
		}()
	})
}
