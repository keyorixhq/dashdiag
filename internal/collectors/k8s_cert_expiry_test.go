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
