package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// makeTestCertPEM creates a self-signed cert PEM with the given validity
// window — mirrors internal/collectors/tls_testhelpers_test.go's helper of
// the same name (unexported there, so it can't be reused across packages).
func makeTestCertPEM(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestScanCertFileMissing(t *testing.T) {
	t.Parallel()
	results := scanCertFile(filepath.Join(t.TempDir(), "nope.pem"), 30, 7)
	if len(results) != 1 || results[0].Level != "ERR" {
		t.Fatalf("a missing file should yield a single ERR result, got: %+v", results)
	}
}

func TestScanCertFileHealthyAndExpiring(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	healthy := filepath.Join(dir, "healthy.pem")
	if err := os.WriteFile(healthy, makeTestCertPEM(t, time.Now().AddDate(0, 0, -1), time.Now().AddDate(0, 6, 0)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	res := scanCertFile(healthy, 30, 7)
	if len(res) != 1 || res[0].Level != "OK" {
		t.Fatalf("a cert expiring in 6 months should be OK, got: %+v", res)
	}

	warn := filepath.Join(dir, "warn.pem")
	if err := os.WriteFile(warn, makeTestCertPEM(t, time.Now().AddDate(0, 0, -1), time.Now().AddDate(0, 0, 15)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	resWarn := scanCertFile(warn, 30, 7)
	if len(resWarn) != 1 || resWarn[0].Level != "WARN" {
		t.Fatalf("a cert expiring in 15 days (warn=30,crit=7) should be WARN, got: %+v", resWarn)
	}

	crit := filepath.Join(dir, "crit.pem")
	if err := os.WriteFile(crit, makeTestCertPEM(t, time.Now().AddDate(0, 0, -1), time.Now().AddDate(0, 0, 2)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	resCrit := scanCertFile(crit, 30, 7)
	if len(resCrit) != 1 || resCrit[0].Level != "CRIT" {
		t.Fatalf("a cert expiring in 2 days should be CRIT, got: %+v", resCrit)
	}
}

// TestScanCertFileNoCommonName covers the subject fallback: a cert with no
// CommonName set must fall back to the full pkix.Name string, not an empty
// subject — every other cert in this file sets CommonName via makeTestCertPEM.
func TestScanCertFileNoCommonName(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"NoCN Corp"}}, // no CommonName
		NotBefore:    time.Now().AddDate(0, 0, -1),
		NotAfter:     time.Now().AddDate(0, 6, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	dir := t.TempDir()
	path := filepath.Join(dir, "nocn.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	res := scanCertFile(path, 30, 7)
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if res[0].Subject == "" || !strings.Contains(res[0].Subject, "NoCN Corp") {
		t.Errorf("a cert with no CommonName should fall back to the full subject string, got: %q", res[0].Subject)
	}
}

// TestScanCertFileNoCertificateBlock guards the "likely a key file" silent
// skip: a PEM file with no CERTIFICATE block returns nil, not an error.
func TestScanCertFileNoCertificateBlock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-real-key")})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if res := scanCertFile(path, 30, 7); res != nil {
		t.Errorf("a file with no CERTIFICATE block should return nil, got: %+v", res)
	}
}

// TestScanCertFileUnparseable guards the malformed-DER path: a CERTIFICATE
// block whose bytes don't parse as an x509 cert must yield an ERR entry, not
// panic or get silently skipped.
func TestScanCertFileUnparseable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not valid DER")})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	res := scanCertFile(path, 30, 7)
	if len(res) != 1 || res[0].Level != "ERR" || !strings.Contains(res[0].Err, "parse error") {
		t.Fatalf("an unparseable CERTIFICATE block should yield a parse-error ERR result, got: %+v", res)
	}
}

func TestAutoDetectCertPathsNoPanic(t *testing.T) {
	t.Parallel()
	// No fixtures are seeded on this host — just confirm it runs without
	// error and returns a (possibly empty) slice.
	_ = autoDetectCertPaths()
}

// TestAutoDetectCertPathsFindsUserCerts covers the "glob found matches"
// branch: every hardcoded /etc/... pattern is unreachable in a test sandbox,
// but the ~/.dsd/certs/*.{crt,pem} pattern respects $HOME, so seeding files
// there exercises the match-append (and dedup-map) path that an empty host
// never reaches.
func TestAutoDetectCertPathsFindsUserCerts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	certsDir := filepath.Join(home, ".dsd", "certs")
	if err := os.MkdirAll(certsDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	crtPath := filepath.Join(certsDir, "a.crt")
	pemPath := filepath.Join(certsDir, "b.pem")
	if err := os.WriteFile(crtPath, []byte("crt"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(pemPath, []byte("pem"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got := autoDetectCertPaths()
	found := map[string]bool{}
	for _, p := range got {
		found[p] = true
	}
	if !found[crtPath] || !found[pemPath] {
		t.Errorf("expected both seeded certs in result, got %v", got)
	}
}

func TestReadEndpointsFile(t *testing.T) {
	t.Parallel()
	if got := readEndpointsFile(""); got != nil {
		t.Errorf("an empty path should return nil, got: %v", got)
	}
	if got := readEndpointsFile(filepath.Join(t.TempDir(), "nope.txt")); got != nil {
		t.Errorf("a missing file should return nil, got: %v", got)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "endpoints.txt")
	content := "# comment\n\nexample.com:443\n  other.example:8443  \n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got := readEndpointsFile(path)
	want := []string{"example.com:443", "other.example:8443"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("readEndpointsFile = %v, want %v (blank lines and comments skipped, trimmed)", got, want)
	}
}

// TestScanRemoteEndpoints exercises the empty-input short-circuit and the
// unreachable-endpoint ERR path (real, read-only network dial to a port that
// should refuse — no external service dependency).
func TestScanRemoteEndpoints(t *testing.T) {
	t.Parallel()
	if got := scanRemoteEndpoints(nil, 30, 7); got != nil {
		t.Errorf("no remotes should return nil, got: %v", got)
	}

	// 127.0.0.1:1 is very unlikely to have a listener; the dial should fail
	// fast and yield a single ERR result rather than hanging or panicking.
	got := scanRemoteEndpoints([]string{" ", "127.0.0.1:1"}, 30, 7)
	if len(got) != 1 || got[0].Level != "ERR" || !got[0].Remote {
		t.Fatalf("an unreachable endpoint should yield a single remote ERR result (blank entries skipped), got: %+v", got)
	}
}

// TestScanRemoteEndpointsHealthy exercises scanRemoteEndpoints' success path
// against a real local TLS listener (httptest's fixed self-signed cert, valid
// until 2084) — no external network dependency, matching the real-I/O
// precedent for this test tier.
func TestScanRemoteEndpointsHealthy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	addr := srv.Listener.Addr().String() // 127.0.0.1:PORT

	got := scanRemoteEndpoints([]string{addr}, 30, 7)
	if len(got) != 1 {
		t.Fatalf("expected exactly one result, got %+v", got)
	}
	if got[0].Level != "OK" || got[0].Err != "" {
		t.Errorf("a live listener with a far-future cert should be OK with no error, got: %+v", got[0])
	}
	if !got[0].SelfSigned {
		t.Errorf("httptest's cert is self-signed and should be flagged as such, got: %+v", got[0])
	}

	// Same live listener, but with warn/crit thresholds set far beyond the
	// cert's remaining days (httptest's fixed cert is valid to 2084) — forces
	// the CRIT band without needing a custom near-expiry cert.
	gotCrit := scanRemoteEndpoints([]string{addr}, 1000000, 500000)
	if len(gotCrit) != 1 || gotCrit[0].Level != "CRIT" {
		t.Fatalf("thresholds far beyond the cert's remaining days should render CRIT, got: %+v", gotCrit)
	}

	// A warnDays threshold beyond the cert's remaining days, but a critDays
	// threshold still below it — the WARN band.
	gotWarn := scanRemoteEndpoints([]string{addr}, 1000000, 1)
	if len(gotWarn) != 1 || gotWarn[0].Level != "WARN" {
		t.Fatalf("a warn threshold beyond the cert's remaining days should render WARN, got: %+v", gotWarn)
	}
}

// newBareTLSCmd builds a bare cobra.Command with the flags runTLS reads via
// cmd.Flags().GetInt/GetBool/GetStringArray/GetString.
func newBareTLSCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Int("warn-days", 30, "")
	f.Int("crit-days", 7, "")
	f.Bool("all", false, "")
	f.StringArray("endpoint", nil, "")
	f.String("endpoints-file", "", "")
	f.Bool("json", false, "")
	f.Bool("plain", false, "")
	return c
}

// TestRunTLSNoCertsFound exercises the "nothing to scan" path: explicit args
// are empty and auto-detect finds nothing in this container.
func TestRunTLSNoCertsFound(t *testing.T) {
	c := newBareTLSCmd()
	out := captureStdout(t, func() {
		if err := runTLS(c, nil); err != nil {
			t.Fatalf("runTLS with nothing to scan: %v", err)
		}
	})
	if !strings.Contains(out, "no certificates found") {
		t.Errorf("no paths/remotes should say so, got:\n%s", out)
	}
}

// TestRunTLSExplicitPathNoCertBlockFound covers the OTHER "no certificates
// found" branch: an explicit path was given (skipping the early empty-args
// short-circuit TestRunTLSNoCertsFound exercises) but the file has no
// CERTIFICATE block (a key file), so scanCertFile returns nil and results
// stays empty after both local and remote scans.
func TestRunTLSExplicitPathNoCertBlockFound(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-real-key")})
	if err := os.WriteFile(keyPath, block, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c := newBareTLSCmd()
	out := captureStdout(t, func() {
		if err := runTLS(c, []string{keyPath}); err != nil {
			t.Fatalf("runTLS with a key-only file: %v", err)
		}
	})
	if !strings.Contains(out, "no certificates found in scanned paths or endpoints") {
		t.Errorf("an explicit path with no CERTIFICATE block should say so, got:\n%s", out)
	}
}

// TestRunTLSExplicitPathJSON exercises runTLS end to end (explicit path,
// --json output) without ever reaching renderTLSResults' os.Exit calls.
func TestRunTLSExplicitPathJSON(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "healthy.pem")
	if err := os.WriteFile(certPath, makeTestCertPEM(t, time.Now().AddDate(0, 0, -1), time.Now().AddDate(0, 6, 0)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c := newBareTLSCmd()
	_ = c.Flags().Set("json", "true")
	out := captureStdout(t, func() {
		if err := runTLS(c, []string{certPath}); err != nil {
			t.Fatalf("runTLS --json: %v", err)
		}
	})
	if !strings.Contains(out, `"certs"`) || !strings.Contains(out, `"status"`) {
		t.Errorf("json mode should emit the certs/status keys, got:\n%s", out)
	}
	if !strings.Contains(out, "test.example.com") {
		t.Errorf("the scanned cert's subject should appear, got:\n%s", out)
	}
}

// TestRunTLSExplicitPathPlainHealthy exercises the plain-mode render path for
// an all-healthy result set — the one renderTLSResults branch that doesn't
// call os.Exit, reached this time through runTLS end to end.
func TestRunTLSExplicitPathPlainHealthy(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "healthy.pem")
	if err := os.WriteFile(certPath, makeTestCertPEM(t, time.Now().AddDate(0, 0, -1), time.Now().AddDate(0, 6, 0)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c := newBareTLSCmd()
	out := captureStdout(t, func() {
		if err := runTLS(c, []string{certPath}); err != nil {
			t.Fatalf("runTLS: %v", err)
		}
	})
	if !strings.Contains(out, "All 1 certificate(s) healthy") {
		t.Errorf("a single healthy cert should summarize as healthy, got:\n%s", out)
	}
}

// TestRunTLSWithEndpointsFile exercises the --endpoints-file flag wiring
// (readEndpointsFile + scanRemoteEndpoints) via runTLS in --json mode, which
// never reaches renderTLSResults' os.Exit calls.
func TestRunTLSWithEndpointsFile(t *testing.T) {
	dir := t.TempDir()
	epFile := filepath.Join(dir, "endpoints.txt")
	if err := os.WriteFile(epFile, []byte("127.0.0.1:1\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c := newBareTLSCmd()
	_ = c.Flags().Set("endpoints-file", epFile)
	_ = c.Flags().Set("json", "true")
	out := captureStdout(t, func() {
		if err := runTLS(c, nil); err != nil {
			t.Fatalf("runTLS --endpoints-file --json: %v", err)
		}
	})
	if !strings.Contains(out, "127.0.0.1:1") {
		t.Errorf("the unreachable endpoint should be recorded as uncheckable, got:\n%s", out)
	}
}
