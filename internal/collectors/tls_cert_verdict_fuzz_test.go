package collectors

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// FuzzParseCertFileExpiryVerdict fuzzes parseCertFile — the TLS collector's
// certificate reader — which feeds untrusted on-disk PEM bytes to two stdlib
// decoders dashdiag calls directly: encoding/pem.Decode and
// crypto/x509.ParseCertificate. The cert files live under paths some of which
// (e.g. /etc/nginx/ssl, /etc/haproxy) can be writable by a non-root service
// account, so the bytes are genuinely attacker-influenced (see tls.go's own
// maxCertDirDepth comment).
//
// This is a VERDICT oracle, not a crash-only one. A diagnostic run as root
// reports cert health; two documented ways it could lie:
//
//  1. Silent drop — a CERTIFICATE block that x509 cannot parse must be recorded
//     as Uncheckable, never discarded into a clean "0 expired". So the number of
//     Uncheckable entries must be >= the number of CERTIFICATE blocks whose
//     x509.ParseCertificate fails.
//  2. Wrong expiry sign — expiryDays() must return a NEGATIVE value for any cert
//     whose NotAfter is already in the past. The int() truncation in expiryDays
//     rounds a cert that expired < 24h ago toward 0 ("expires in 0 days" / about
//     to break) instead of < 0 (already down) unless the explicit sign fix holds.
//     That mis-buckets an already-expired cert as merely Expiring — a WRONG
//     VERDICT that hides a down service. The offsetHours fuzz argument sweeps
//     `now` across the seed certs' NotAfter boundary to exercise exactly this.
//
// INVARIANT (see INVARIANTS.d note): parseCertFile never silently drops an
// unparseable CERTIFICATE block, and expiryDays(notAfter,now)<0 whenever
// notAfter is before now.
//
// What this oracle does NOT verify: that a PARSEABLE non-CA cert always surfaces
// as a CertInfo (the self-signed-CA >365d skip path is intentional and not
// re-derived here), the correctness of Subject/Issuer truncation, or anything
// about remote-endpoint TLS (this is the file path only).

var fuzzCertBase = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

// makeCertPEM builds a self-signed ed25519 CERTIFICATE PEM whose NotAfter is at.
func makeCertPEM(tb testing.TB, cn string, notBefore, notAfter time.Time) []byte {
	tb.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		tb.Fatalf("createcert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func FuzzParseCertFileExpiryVerdict(f *testing.F) {
	// Seeds: a valid cert, a cert that expired just under 24h before base (the
	// rounding-to-zero trap), a long-expired cert, a non-cert PEM block, two
	// concatenated certs, and assorted garbage.
	valid := makeCertPEM(f, "valid.example", fuzzCertBase.Add(-24*time.Hour), fuzzCertBase.Add(400*24*time.Hour))
	expiredSoon := makeCertPEM(f, "expired-soon.example", fuzzCertBase.Add(-48*time.Hour), fuzzCertBase) // NotAfter == base
	longExpired := makeCertPEM(f, "long-expired.example", fuzzCertBase.Add(-800*24*time.Hour), fuzzCertBase.Add(-400*24*time.Hour))

	f.Add(valid, int32(0))
	f.Add(expiredSoon, int32(1))  // now = base + 1h: cert is 1h expired -> MUST be <0
	f.Add(expiredSoon, int32(23)) // now = base + 23h: still <24h expired -> MUST be <0
	f.Add(longExpired, int32(0))
	f.Add(append(append([]byte{}, valid...), expiredSoon...), int32(2))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), int32(0))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nnotbase64!!!\n-----END CERTIFICATE-----\n"), int32(0))
	f.Add([]byte("garbage not pem"), int32(0))
	f.Add([]byte(""), int32(0))

	f.Fuzz(func(t *testing.T, data []byte, offsetHours int32) {
		now := fuzzCertBase.Add(time.Duration(offsetHours) * time.Hour)

		dir := t.TempDir()
		p := filepath.Join(dir, "cert.pem")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatalf("write temp: %v", err)
		}

		results, uncheckable := parseCertFile(p, now)

		// (1) No silent drop: every CERTIFICATE block that x509 cannot parse must
		// have produced an Uncheckable entry.
		var failParse int
		rest := data
		for len(rest) > 0 {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				failParse++
			}
		}
		if len(uncheckable) < failParse {
			t.Fatalf("silent drop: %d CERTIFICATE blocks failed to parse but only %d uncheckable recorded", failParse, len(uncheckable))
		}

		// (2) Expiry sign: for every cert that DOES parse, if its NotAfter is
		// before now, expiryDays must be strictly negative (never 0).
		rest = data
		for len(rest) > 0 {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			d := expiryDays(cert.NotAfter, now)
			if cert.NotAfter.Before(now) && d >= 0 {
				t.Fatalf("expiryDays returned %d for a cert that expired at %v (now=%v): an already-expired cert must be < 0, not mis-bucketed as Expiring", d, cert.NotAfter, now)
			}
			if !cert.NotAfter.Before(now) && d < 0 {
				t.Fatalf("expiryDays returned %d for a still-valid cert (NotAfter=%v, now=%v)", d, cert.NotAfter, now)
			}
		}

		// Keep results referenced so the collector path is fully exercised.
		_ = results
	})
}
