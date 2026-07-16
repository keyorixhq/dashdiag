package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestApply_ChmodFails exercises the os.Chmod error branch in Apply: the
// staged temp file exists and the checksum matches, but chmod is injected to
// return an error, so Apply must return before renaming.
func TestApply_ChmodFails(t *testing.T) {
	t.Parallel()

	oldKey := signingPublicKey
	signingPublicKey = ""
	defer func() { signingPublicKey = oldKey }()

	payload := []byte("binary-payload")
	sum := sha256.Sum256(payload)
	sumHex := hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/bin", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	})
	mux.HandleFunc("/sums", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "%s  %s\n", sumHex, AssetName())
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rel := &Release{TagName: "v1", Assets: []Asset{
		{Name: AssetName(), URL: srv.URL + "/bin"},
		{Name: "checksums.txt", URL: srv.URL + "/sums"},
	}}

	dir := t.TempDir()
	target := filepath.Join(dir, "dsd")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	oldExe := executable
	executable = func() (string, error) { return target, nil }
	defer func() { executable = oldExe }()

	chmodErr := errors.New("chmod injected failure")
	oldChmod := osChmod
	osChmod = func(_ string, _ os.FileMode) error { return chmodErr }
	defer func() { osChmod = oldChmod }()

	_, err := Apply(context.Background(), rel)
	if err == nil {
		t.Fatal("expected an error from the injected chmod failure")
	}
	if !strings.Contains(err.Error(), "chmod injected failure") {
		t.Fatalf("expected chmod error to propagate, got: %v", err)
	}

	// The original binary must be untouched.
	got, _ := os.ReadFile(target)
	if string(got) != "old" {
		t.Errorf("binary was mutated despite chmod failure: %q", got)
	}
}
