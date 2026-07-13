package baseline

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWriteAndCloseFn_DefaultWriteFails exercises the default writeAndCloseFn
// implementation's write-failure branch directly: writing to an
// already-closed *os.File fails, and the function must still attempt to
// close it (harmlessly, on an already-closed file) before returning the
// write error. Not otherwise reachable through Save* without a real
// disk-full/IO-error condition on a freshly created temp file.
func TestWriteAndCloseFn_DefaultWriteFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "wf-*.tmp")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing fixture file: %v", err)
	}

	if err := writeAndCloseFn(f, []byte("data")); err == nil {
		t.Error("writing to an already-closed file should error")
	}
}

// TestWriteAndCloseFn_DefaultSuccess exercises the default implementation's
// success path directly (write then close both succeed).
func TestWriteAndCloseFn_DefaultSuccess(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "wf-*.tmp")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}

	if err := writeAndCloseFn(f, []byte("hello")); err != nil {
		t.Fatalf("writeAndCloseFn: %v", err)
	}
	got, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("file content = %q, want %q", got, "hello")
	}
}

// TestSavers_PropagateWriteAndCloseFailure swaps the shared writeAndCloseFn
// package var to inject a write/close failure into each Save* function's
// call site — including SaveBaseline's SECOND call site (the "-latest.json"
// temp file, reached only after the first write/rename succeeds), which a
// simple always-fail stub can't reach on its own.
//
// NOT t.Parallel(): swaps a package-level var shared with every other test
// in this file/package, following the same serialization precedent as
// hashSSHConfigFilesFn/testSSHHashes in security_baseline_test.go.
func TestSavers_PropagateWriteAndCloseFailure(t *testing.T) {
	orig := writeAndCloseFn
	defer func() { writeAndCloseFn = orig }()

	home := t.TempDir()
	t.Setenv("HOME", home)
	hostname, _ := os.Hostname()

	// SaveBaseline's FIRST writeAndCloseFn call (the timestamped snapshot file).
	writeAndCloseFn = func(f *os.File, _ []byte) error {
		_ = f.Close()
		return fmt.Errorf("injected write failure")
	}
	snap := makeSnap(hostname, "v1", "cpu", "OK")
	if err := SaveBaseline(snap); err == nil {
		t.Error("SaveBaseline should surface an injected failure on the first temp file")
	}

	// SaveBaseline's SECOND writeAndCloseFn call (the "-latest.json" temp
	// file) — let the first call through, fail the second.
	calls := 0
	writeAndCloseFn = func(f *os.File, data []byte) error {
		calls++
		if calls == 1 {
			return orig(f, data)
		}
		_ = f.Close()
		return fmt.Errorf("injected write failure on second temp file")
	}
	if err := SaveBaseline(snap); err == nil {
		t.Error("SaveBaseline should surface an injected failure on the second (latest) temp file")
	}
	if calls != 2 {
		t.Errorf("expected writeAndCloseFn to be called twice, got %d", calls)
	}

	// SaveGolden and SaveSecurityBaseline each have exactly one call site.
	writeAndCloseFn = func(f *os.File, _ []byte) error {
		_ = f.Close()
		return fmt.Errorf("injected write failure")
	}
	gsnap := &Snapshot{Hostname: "h", Version: "v1", Timestamp: time.Now()}
	if err := SaveGolden(gsnap, "prod"); err == nil {
		t.Error("SaveGolden should surface an injected write/close failure")
	}
	if err := SaveSecurityBaseline(&SecurityBaseline{Hostname: "h"}); err == nil {
		t.Error("SaveSecurityBaseline should surface an injected write/close failure")
	}
}

// TestSaveGolden_SecondCallOverwrites confirms a second SaveGolden under the
// same name replaces the first save's content — SaveGolden has no
// latest/prev rotation (unlike SaveBaseline), so the correctness property to
// pin here is straightforward overwrite, not rotation.
func TestSaveGolden_SecondCallOverwrites(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	first := &Snapshot{Hostname: "h", Version: "v1", Timestamp: time.Now()}
	second := &Snapshot{Hostname: "h", Version: "v2", Timestamp: time.Now()}

	if err := SaveGolden(first, "prod"); err != nil {
		t.Fatalf("first SaveGolden: %v", err)
	}
	if err := SaveGolden(second, "prod"); err != nil {
		t.Fatalf("second SaveGolden: %v", err)
	}

	loaded, err := LoadGolden("prod")
	if err != nil {
		t.Fatalf("LoadGolden: %v", err)
	}
	if loaded.Version != "v2" {
		t.Errorf("LoadGolden after two saves = %q, want v2 (second save's content)", loaded.Version)
	}

	// No rotation artifact should appear — golden baselines have no -prev concept.
	entries, err := os.ReadDir(filepath.Join(dir, ".dsd", "golden"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected exactly one golden file after two saves to the same name, got %d: %v", len(entries), entries)
	}
}

// TestSaveSecurityBaseline_SecondCallOverwrites confirms a second
// SaveSecurityBaseline replaces the first save's content in place —
// SaveSecurityBaseline writes a single fixed path with no rotation.
func TestSaveSecurityBaseline_SecondCallOverwrites(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	first := &SecurityBaseline{Hostname: "h", KnownSUIDs: []string{"/usr/bin/sudo"}}
	second := &SecurityBaseline{Hostname: "h", KnownSUIDs: []string{"/usr/bin/sudo", "/usr/local/bin/new"}}

	if err := SaveSecurityBaseline(first); err != nil {
		t.Fatalf("first SaveSecurityBaseline: %v", err)
	}
	if err := SaveSecurityBaseline(second); err != nil {
		t.Fatalf("second SaveSecurityBaseline: %v", err)
	}

	loaded, err := LoadSecurityBaseline()
	if err != nil {
		t.Fatalf("LoadSecurityBaseline: %v", err)
	}
	if len(loaded.KnownSUIDs) != 2 {
		t.Errorf("LoadSecurityBaseline after two saves = %+v, want the second save's 2 SUIDs", loaded.KnownSUIDs)
	}
}
