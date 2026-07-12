package source

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteJSONMarshalFailure exercises writeJSON's json.MarshalIndent
// failure path — a value that cannot be marshalled (a bare channel).
func TestWriteJSONMarshalFailure(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "unmarshalable.json")
	err := writeJSON(path, make(chan int))
	if err == nil {
		t.Fatal("writeJSON of an unmarshalable value should fail")
	}
}

// TestWriteJSONWriteFailure exercises writeJSON's os.WriteFile failure path —
// a destination directory that does not exist.
func TestWriteJSONWriteFailure(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "no-such-subdir", "out.json")
	err := writeJSON(path, map[string]string{"a": "b"})
	if err == nil {
		t.Fatal("writeJSON into a nonexistent directory should fail")
	}
}

// TestReadJSONReadFailure exercises readJSON's os.ReadFile failure path — a
// path that does not exist.
func TestReadJSONReadFailure(t *testing.T) {
	t.Parallel()

	var v map[string]string
	err := readJSON(filepath.Join(t.TempDir(), "missing.json"), &v)
	if err == nil {
		t.Fatal("readJSON of a missing file should fail")
	}
}

// TestReadJSONUnmarshalFailure exercises readJSON's json.Unmarshal failure
// path — a file containing invalid JSON.
func TestReadJSONUnmarshalFailure(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o644); err != nil {
		t.Fatalf("writing raw bad json: %v", err)
	}
	var v map[string]string
	if err := readJSON(path, &v); err == nil {
		t.Fatal("readJSON of invalid JSON content should fail")
	}
}
