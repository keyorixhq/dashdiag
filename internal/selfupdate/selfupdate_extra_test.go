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

func TestNormalize(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain", "1.2.3", "1.2.3"},
		{"v-prefixed", "v1.2.3", "1.2.3"},
		{"whitespace", "  v1.2.3  ", "1.2.3"},
		{"dev", "dev", ""},
		{"empty", "", ""},
		{"major-minor-only", "v1.2", "1.2"},
		{"prerelease suffix", "v1.2.3-rc1", "1.2.3-rc1"},
		{"build suffix", "v1.2.3+build5", "1.2.3+build5"},
		{"non-numeric part", "v1.x.3", ""},
		{"empty part", "v1..3", ""},
		{"too many parts, 4th makes 3rd part unparseable", "v1.2.3.4", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := normalize(c.in); got != c.want {
				t.Errorf("normalize(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestVersionParts(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want [3]int
	}{
		{"full", "v1.2.3", [3]int{1, 2, 3}},
		{"major-minor", "v1.2", [3]int{1, 2, 0}},
		{"unparseable", "dev", [3]int{0, 0, 0}},
		{"prerelease", "v1.2.3-rc1", [3]int{1, 2, 3}},
		{"too many parts unparseable", "v1.2.3.4", [3]int{0, 0, 0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := versionParts(c.in); got != c.want {
				t.Errorf("versionParts(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestIsCleanRelease(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"major-minor", "v1.2", true},
		{"major-minor-patch", "v1.2.3", true},
		{"no-v-prefix", "1.2.3", true},
		{"single-part", "v1", false},
		{"too-many-parts", "v1.2.3.4", false},
		{"empty-part", "v1..3", false},
		{"non-numeric", "v1.2.x", false},
		{"dev", "dev", false},
		{"describe-string", "v0.6.1-12-gabc123", false},
		{"prerelease", "v1.2.3-rc1", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isCleanRelease(c.in); got != c.want {
				t.Errorf("isCleanRelease(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestLatestRelease_ErrorPaths(t *testing.T) {
	t.Run("non-200 status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		oldBase := apiBase
		apiBase = srv.URL
		defer func() { apiBase = oldBase }()

		_, err := LatestRelease(context.Background())
		if err == nil || !strings.Contains(err.Error(), "404") {
			t.Fatalf("expected 404 error, got %v", err)
		}
	})

	t.Run("malformed JSON body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("{not json"))
		}))
		defer srv.Close()
		oldBase := apiBase
		apiBase = srv.URL
		defer func() { apiBase = oldBase }()

		_, err := LatestRelease(context.Background())
		if err == nil {
			t.Fatal("expected JSON decode error")
		}
	})

	t.Run("empty tag name", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"tag_name":""}`))
		}))
		defer srv.Close()
		oldBase := apiBase
		apiBase = srv.URL
		defer func() { apiBase = oldBase }()

		_, err := LatestRelease(context.Background())
		if err == nil || !strings.Contains(err.Error(), "no tag") {
			t.Fatalf("expected 'no tag' error, got %v", err)
		}
	})

	t.Run("request creation error", func(t *testing.T) {
		oldBase := apiBase
		// A control character in the URL makes http.NewRequestWithContext fail.
		apiBase = "http://\x7f"
		defer func() { apiBase = oldBase }()

		_, err := LatestRelease(context.Background())
		if err == nil {
			t.Fatal("expected error constructing the request")
		}
	})

	t.Run("client Do error (unreachable host)", func(t *testing.T) {
		oldBase := apiBase
		apiBase = "http://127.0.0.1:1" // nothing listens here
		defer func() { apiBase = oldBase }()

		_, err := LatestRelease(context.Background())
		if err == nil {
			t.Fatal("expected a network error")
		}
	})
}

func TestFindAsset(t *testing.T) {
	assets := []Asset{{Name: "a"}, {Name: "b"}}
	if got := findAsset(assets, "b"); got == nil || got.Name != "b" {
		t.Errorf("findAsset(b) = %+v", got)
	}
	if got := findAsset(assets, "missing"); got != nil {
		t.Errorf("findAsset(missing) = %+v, want nil", got)
	}
}

func TestChecksumFor(t *testing.T) {
	data := []byte("aaa  file-one\nbbb  file-two\n")
	t.Run("found", func(t *testing.T) {
		got, err := checksumFor(data, "file-two")
		if err != nil || got != "bbb" {
			t.Errorf("checksumFor = %q, %v", got, err)
		}
	})
	t.Run("not found", func(t *testing.T) {
		_, err := checksumFor(data, "missing")
		if err == nil {
			t.Fatal("expected error for missing checksum entry")
		}
	})
}

func TestHTTPGet_ErrorPaths(t *testing.T) {
	client := &http.Client{}

	t.Run("bad status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		_, err := httpGet(context.Background(), client, srv.URL)
		if err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("expected 403 error, got %v", err)
		}
	})

	t.Run("request creation error", func(t *testing.T) {
		_, err := httpGet(context.Background(), client, "http://\x7f")
		if err == nil {
			t.Fatal("expected request construction error")
		}
	})

	t.Run("unreachable host", func(t *testing.T) {
		_, err := httpGet(context.Background(), client, "http://127.0.0.1:1")
		if err == nil {
			t.Fatal("expected connection error")
		}
	})
}

func TestFetchBytes_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := fetchBytes(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected fetchBytes error on 500")
	}
}

// TestFetchBytes_SizeCapped is the regression test for internal-selfupdate-01-02:
// fetchBytes (used for checksums.txt and the .minisig signature) must refuse a
// response larger than maxAPIResponseBytes rather than buffering it unbounded
// into memory.
func TestFetchBytes_SizeCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := make([]byte, 64*1024)
		for written := 0; written < maxAPIResponseBytes+len(chunk); written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	_, err := fetchBytes(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected fetchBytes to refuse an oversized response")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("expected a size-cap error, got: %v", err)
	}
}

// TestLatestRelease_SizeCapped is the same regression for the GitHub releases
// API JSON path: an oversized body must fail rather than be decoded unbounded.
func TestLatestRelease_SizeCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"tag_name":"v9.9.9","assets":[`)
		filler := strings.Repeat("a", 1024)
		for written := 0; written < maxAPIResponseBytes+len(filler); written += len(filler) {
			fmt.Fprintf(w, `{"name":"%s","browser_download_url":"x"},`, filler)
		}
		fmt.Fprint(w, `{"name":"end","browser_download_url":"x"}]}`)
	}))
	defer srv.Close()
	origBase := apiBase
	apiBase = srv.URL
	defer func() { apiBase = origBase }()

	_, err := LatestRelease(context.Background())
	if err == nil {
		t.Fatal("expected LatestRelease to fail decoding an oversized response")
	}
}

func TestDownloadToTemp_Errors(t *testing.T) {
	t.Run("httpGet fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		_, _, err := downloadToTemp(context.Background(), srv.URL, t.TempDir())
		if err == nil {
			t.Fatal("expected error when the download itself fails")
		}
	})

	t.Run("target dir does not exist", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("payload"))
		}))
		defer srv.Close()
		missing := filepath.Join(t.TempDir(), "does", "not", "exist")
		_, _, err := downloadToTemp(context.Background(), srv.URL, missing)
		if err == nil || !strings.Contains(err.Error(), "cannot stage update") {
			t.Fatalf("expected 'cannot stage update' error, got %v", err)
		}
	})

	t.Run("success computes sha256", func(t *testing.T) {
		payload := []byte("hello world")
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(payload)
		}))
		defer srv.Close()
		dir := t.TempDir()
		path, sum, err := downloadToTemp(context.Background(), srv.URL, dir)
		if err != nil {
			t.Fatalf("downloadToTemp: %v", err)
		}
		defer os.Remove(path)
		got, _ := os.ReadFile(path)
		if string(got) != string(payload) {
			t.Errorf("downloaded content = %q, want %q", got, payload)
		}
		if sum == "" {
			t.Error("expected a non-empty checksum")
		}
	})
}

// TestApply_ErrorPaths covers the early-return error branches in Apply that
// TestApply_EndToEnd / TestApply_ChecksumMismatch don't exercise.
func TestApply_ErrorPaths(t *testing.T) {
	oldKey := signingPublicKey
	signingPublicKey = ""
	defer func() { signingPublicKey = oldKey }()

	t.Run("no asset for this platform", func(t *testing.T) {
		rel := &Release{TagName: "v1", Assets: []Asset{}}
		_, err := Apply(context.Background(), rel)
		if err == nil || !strings.Contains(err.Error(), "no asset") {
			t.Fatalf("expected 'no asset' error, got %v", err)
		}
	})

	t.Run("no checksums.txt", func(t *testing.T) {
		rel := &Release{TagName: "v1", Assets: []Asset{{Name: AssetName(), URL: "http://example/bin"}}}
		_, err := Apply(context.Background(), rel)
		if err == nil || !strings.Contains(err.Error(), "checksums.txt") {
			t.Fatalf("expected 'checksums.txt' error, got %v", err)
		}
	})

	t.Run("fetchBytes for checksums fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		rel := &Release{TagName: "v1", Assets: []Asset{
			{Name: AssetName(), URL: "http://example/bin"},
			{Name: "checksums.txt", URL: srv.URL},
		}}
		_, err := Apply(context.Background(), rel)
		if err == nil {
			t.Fatal("expected error fetching checksums.txt")
		}
	})

	t.Run("checksum missing for asset", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("aaa  some-other-file\n"))
		}))
		defer srv.Close()
		rel := &Release{TagName: "v1", Assets: []Asset{
			{Name: AssetName(), URL: "http://example/bin"},
			{Name: "checksums.txt", URL: srv.URL},
		}}
		_, err := Apply(context.Background(), rel)
		if err == nil || !strings.Contains(err.Error(), "no checksum for") {
			t.Fatalf("expected 'no checksum for' error, got %v", err)
		}
	})

	t.Run("executable() fails", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/bin", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("x")) })
		mux.HandleFunc("/sums", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("aaa  " + AssetName() + "\n"))
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		rel := &Release{TagName: "v1", Assets: []Asset{
			{Name: AssetName(), URL: srv.URL + "/bin"},
			{Name: "checksums.txt", URL: srv.URL + "/sums"},
		}}

		oldExe := executable
		executable = func() (string, error) { return "", errors.New("no executable") }
		defer func() { executable = oldExe }()

		_, err := Apply(context.Background(), rel)
		if err == nil || !strings.Contains(err.Error(), "no executable") {
			t.Fatalf("expected executable() error, got %v", err)
		}
	})

	t.Run("downloadToTemp fails (bad binary URL)", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/sums", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("aaa  " + AssetName() + "\n"))
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		rel := &Release{TagName: "v1", Assets: []Asset{
			{Name: AssetName(), URL: "http://127.0.0.1:1"},
			{Name: "checksums.txt", URL: srv.URL + "/sums"},
		}}

		dir := t.TempDir()
		target := filepath.Join(dir, "dsd")
		_ = os.WriteFile(target, []byte("old"), 0o755)
		oldExe := executable
		executable = func() (string, error) { return target, nil }
		defer func() { executable = oldExe }()

		_, err := Apply(context.Background(), rel)
		if err == nil {
			t.Fatal("expected downloadToTemp error")
		}
	})
}

// TestApply_SignatureVerificationFails covers the verifyChecksumsSignature
// error branch in Apply: a build with a signing key configured must refuse to
// apply an update whose release ships no checksums.txt.minisig asset, before
// ever reaching the checksum/download steps.
func TestApply_SignatureVerificationFails(t *testing.T) {
	oldKey := signingPublicKey
	signingPublicKey = "some-configured-key"
	defer func() { signingPublicKey = oldKey }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("aaa  " + AssetName() + "\n"))
	}))
	defer srv.Close()

	rel := &Release{TagName: "v1", Assets: []Asset{
		{Name: AssetName(), URL: "http://example/bin"},
		{Name: "checksums.txt", URL: srv.URL},
	}}

	_, err := Apply(context.Background(), rel)
	if err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("expected 'not signed' error from signature verification, got %v", err)
	}
}

// TestApply_ChmodAndRenameFail exercises the os.Chmod and os.Rename error
// branches in Apply by pointing "exe" (the resolved running-binary path) at a
// directory that does not exist, so filepath.Dir(exe) — where downloadToTemp
// stages the file — also does not exist. downloadToTemp itself fails first in
// that case, so instead this drives the failure via a target directory that
// exists but is not writable enough to rename into, while downloadToTemp still
// succeeds because os.CreateTemp falls back within the same (writable) dir.
//
// The reliable way to isolate Chmod/Rename specifically (without racing
// downloadToTemp) is to remove the staged temp file the instant it is created,
// using a directory FileSystemWatch substitute: since the package does not
// expose a hook there, this test instead verifies the Rename failure branch by
// targeting an "exe" path that is itself a directory — os.Rename onto an
// existing non-empty directory fails on all platforms, giving a deterministic,
// non-racy repro of the Apply post-download failure path.
func TestApply_ChmodAndRenameFail(t *testing.T) {
	oldKey := signingPublicKey
	signingPublicKey = ""
	defer func() { signingPublicKey = oldKey }()

	payload := []byte("new-binary-contents")
	sum := sha256.Sum256(payload)
	sumHex := hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/bin", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(payload) })
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
	// "exe" is a non-empty directory, not a regular file: filepath.Dir(exe)
	// still resolves to dir (writable, so downloadToTemp/Chmod succeed), but
	// the final os.Rename(tmp, exe) fails because exe is an existing
	// non-empty directory.
	target := filepath.Join(dir, "dsd")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "occupied"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldExe := executable
	executable = func() (string, error) { return target, nil }
	defer func() { executable = oldExe }()

	_, err := Apply(context.Background(), rel)
	if err == nil || !strings.Contains(err.Error(), "replacing") {
		t.Fatalf("expected a 'replacing ... failed' error from a non-empty-directory rename target, got %v", err)
	}
}
