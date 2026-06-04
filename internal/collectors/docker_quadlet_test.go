//go:build linux || darwin

package collectors

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestQuadletServiceUnit(t *testing.T) {
	cases := map[string]string{
		"test-nginx.container": "test-nginx.service",
		"myapp.pod":            "myapp.service",
		"db.container":         "db.service",
		"web-stack.pod":        "web-stack.service",
	}
	for in, want := range cases {
		if got := quadletServiceUnit(in); got != want {
			t.Errorf("quadletServiceUnit(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQuadletBaseName(t *testing.T) {
	cases := map[string]string{
		"test-nginx.container": "test-nginx",
		"myapp.pod":            "myapp",
		// Only the .container/.pod suffix is stripped — nothing else.
		"odd.name.container": "odd.name",
	}
	for in, want := range cases {
		if got := quadletBaseName(in); got != want {
			t.Errorf("quadletBaseName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScanQuadletFiles(t *testing.T) {
	dir := t.TempDir()
	// Quadlet files that should be picked up.
	writeFile(t, dir, "test-nginx.container")
	writeFile(t, dir, "myapp.pod")
	// Non-quadlet files that must be ignored.
	writeFile(t, dir, "README.md")
	writeFile(t, dir, "test-nginx.network")
	// A subdirectory must be skipped (not recursed, not treated as a file).
	if err := os.Mkdir(filepath.Join(dir, "sub.container"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Include a nonexistent directory — it must be skipped silently.
	files := scanQuadletFiles([]string{dir, filepath.Join(dir, "does-not-exist")})

	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.name)
		if f.path != filepath.Join(dir, f.name) {
			t.Errorf("file %q: path = %q, want %q", f.name, f.path, filepath.Join(dir, f.name))
		}
	}
	sort.Strings(names)
	want := []string{"myapp.pod", "test-nginx.container"}
	if len(names) != len(want) {
		t.Fatalf("scanQuadletFiles found %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("scanQuadletFiles[%d] = %q, want %q", i, names[i], want[i])
		}
	}
}

func TestScanQuadletFilesEmpty(t *testing.T) {
	// No directories exist → nil, never an error.
	if got := scanQuadletFiles([]string{"/nonexistent/a", "/nonexistent/b"}); got != nil {
		t.Errorf("scanQuadletFiles on absent dirs = %v, want nil", got)
	}
}

func TestParseQuadletState(t *testing.T) {
	cases := []struct {
		name       string
		output     string
		wantActive bool
		wantFailed bool
		wantState  string
	}{
		{
			name:       "failed unit",
			output:     "ActiveState=failed\nSubState=failed\nLoadState=loaded\n",
			wantActive: false,
			wantFailed: true,
			wantState:  "failed",
		},
		{
			name:       "active unit",
			output:     "ActiveState=active\nSubState=running\nLoadState=loaded\n",
			wantActive: true,
			wantFailed: false,
			wantState:  "active",
		},
		{
			name:       "inactive unit",
			output:     "ActiveState=inactive\nSubState=dead\nLoadState=loaded\n",
			wantActive: false,
			wantFailed: false,
			wantState:  "inactive",
		},
		{
			name:       "empty output",
			output:     "",
			wantActive: false,
			wantFailed: false,
			wantState:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			active, failed, state := parseQuadletState(tc.output)
			if active != tc.wantActive || failed != tc.wantFailed || state != tc.wantState {
				t.Errorf("parseQuadletState(%q) = (%v, %v, %q), want (%v, %v, %q)",
					tc.output, active, failed, state, tc.wantActive, tc.wantFailed, tc.wantState)
			}
		})
	}
}

// podmanInstalled gates quadlet scanning when the API socket is inactive,
// so it must reflect podman's presence on PATH.
func TestPodmanInstalled(t *testing.T) {
	dir := t.TempDir()

	// Empty PATH → podman not found.
	t.Setenv("PATH", dir)
	if podmanInstalled() {
		t.Fatal("podmanInstalled() = true with podman absent from PATH, want false")
	}

	// Drop a fake executable named podman on PATH → found.
	fake := filepath.Join(dir, "podman")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !podmanInstalled() {
		t.Fatal("podmanInstalled() = false with podman on PATH, want true")
	}
}

// quadletFilesPresent backs PodmanQuadletsPresent — it gates whether dsd health
// runs the Docker collector on a socket-inactive Podman host.
func TestQuadletFilesPresent(t *testing.T) {
	t.Run("present with .container file", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "test-nginx.container")
		if !quadletFilesPresent(dir) {
			t.Error("expected true with a .container file present")
		}
	})
	t.Run("present with .pod file", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "myapp.pod")
		if !quadletFilesPresent(dir) {
			t.Error("expected true with a .pod file present")
		}
	})
	t.Run("absent when dir empty", func(t *testing.T) {
		dir := t.TempDir()
		// A non-quadlet file must not count.
		writeFile(t, dir, "README.md")
		if quadletFilesPresent(dir) {
			t.Error("expected false for a dir with no quadlet files")
		}
	})
	t.Run("absent when dir missing", func(t *testing.T) {
		if quadletFilesPresent(filepath.Join(t.TempDir(), "does-not-exist")) {
			t.Error("expected false for a missing directory")
		}
	})
}

func writeFile(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}
