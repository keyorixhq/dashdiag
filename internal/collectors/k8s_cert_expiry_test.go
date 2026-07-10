package collectors

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// writeTestCert generates a self-signed cert with the given NotAfter and writes
// it PEM-encoded to dir/name.
func writeTestCert(t *testing.T, dir, name string, notAfter time.Time) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestCheckCertExpiry is a regression guard for the replay-hermeticity bug: the
// function must compute cert age against NowViaSource() (capture-time under
// `dsd replay`/`dsd migrate certify`), not time.Now() (the replaying machine's
// clock) — otherwise CertExpirySoon/CertExpiredNames flip depending on when the
// bundle happens to be replayed, or a cert genuinely fine at capture time reads
// as freshly EXPIRED once real wall-time passes NotAfter.
func TestCheckCertExpiry(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeTestCert(t, dir, "expired.crt", now.Add(-24*time.Hour))
	writeTestCert(t, dir, "soon.crt", now.Add(5*24*time.Hour))
	writeTestCert(t, dir, "healthy.crt", now.Add(180*24*time.Hour))

	layer := &models.K8sOSLayer{}
	checkCertExpiry(dir, layer)

	if len(layer.CertExpiredNames) != 1 || layer.CertExpiredNames[0] != "expired.crt" {
		t.Errorf("CertExpiredNames = %v, want [expired.crt]", layer.CertExpiredNames)
	}
	if !layer.CertExpirySoon {
		t.Fatal("expected CertExpirySoon=true for the 5-day cert")
	}
	if layer.CertExpirySoonDays < 4 || layer.CertExpirySoonDays > 5 {
		t.Errorf("CertExpirySoonDays = %d, want ~5", layer.CertExpirySoonDays)
	}
}

// TestCheckCertExpiry_UnreadableOrGarbledSkipped guards the three early
// "continue" branches: a glob match that can't be read (permission/race),
// a file that isn't PEM at all, and PEM content whose DER doesn't parse as an
// X.509 certificate. None of these should panic or record a bogus entry.
func TestCheckCertExpiry_UnreadableOrGarbledSkipped(t *testing.T) {
	dir := t.TempDir()

	// Not PEM at all — pem.Decode returns a nil block.
	if err := os.WriteFile(filepath.Join(dir, "notpem.crt"), []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Valid PEM armor, but garbage DER inside — x509.ParseCertificate fails.
	garbledPEM := "-----BEGIN CERTIFICATE-----\n" + "AAAA\n" + "-----END CERTIFICATE-----\n"
	if err := os.WriteFile(filepath.Join(dir, "garbled.crt"), []byte(garbledPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	// A real, valid, healthy cert alongside the two bad ones — must still be
	// scanned without a bad sibling short-circuiting the whole directory.
	writeTestCert(t, dir, "healthy.crt", time.Now().Add(180*24*time.Hour))

	layer := &models.K8sOSLayer{}
	checkCertExpiry(dir, layer)

	if len(layer.CertExpiredNames) != 0 {
		t.Errorf("CertExpiredNames = %v, want none (only garbled/non-PEM/healthy certs present)", layer.CertExpiredNames)
	}
	if layer.CertExpirySoon {
		t.Errorf("CertExpirySoon = true, want false (only the healthy cert parsed)")
	}
}

// TestCheckCertExpiry_UnreadableFileSkipped guards the readFile-error continue
// branch: a glob match naming a file that no longer exists (e.g. a race
// between listing and reading, or a dangling permission issue) must be
// skipped rather than erroring out.
func TestCheckCertExpiry_UnreadableFileSkipped(t *testing.T) {
	dir := t.TempDir()
	// Create then remove so glob-time and read-time disagree — readFile fails.
	ghost := filepath.Join(dir, "ghost.crt")
	if err := os.WriteFile(ghost, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeTestCert(t, dir, "healthy.crt", time.Now().Add(180*24*time.Hour))
	if err := os.Remove(ghost); err != nil {
		t.Fatal(err)
	}

	layer := &models.K8sOSLayer{}
	checkCertExpiry(dir, layer)
	if len(layer.CertExpiredNames) != 0 || layer.CertExpirySoon {
		t.Errorf("layer = %+v, want no expiry findings from the vanished file", layer)
	}
}
