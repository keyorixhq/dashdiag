package collectors

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TLSCollector scans well-known certificate paths for expiring or expired certs.
// Only scans non-CA-bundle files — individual service certs, not system trust anchors.
type TLSCollector struct{}

func NewTLSCollector() *TLSCollector { return &TLSCollector{} }

func (c *TLSCollector) Name() string           { return "TLS" }
func (c *TLSCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *TLSCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.TLSInfo{}
	now := time.Now()

	for _, path := range tlsCertPaths() {
		select {
		case <-ctx.Done():
			return info, nil
		default:
		}
		certs := scanCertPath(path, now)
		info.Certs = append(info.Certs, certs...)
	}

	for _, cert := range info.Certs {
		if cert.ExpiresIn < 0 {
			info.Expired++
		} else if cert.ExpiresIn <= 30 {
			info.Expiring++
		}
	}
	return info, nil
}

// tlsCertPaths returns paths to scan for service certificates.
// Excludes CA bundle directories — too many files, all long-lived.
// Excludes /etc/ssl/certs/ (system CA bundle) and /etc/ssl/cert.pem (macOS bundle).
func tlsCertPaths() []string {
	if runtime.GOOS == "darwin" {
		return []string{
			"/usr/local/etc/ssl",
			"/opt/homebrew/etc/ssl",
			"/opt/homebrew/etc/nginx",
			"/usr/local/etc/nginx",
		}
	}
	return []string{
		"/etc/ssl/private",      // Debian/Ubuntu service certs (not the CA bundle)
		"/etc/pki/tls/private",  // RHEL service certs
		"/etc/letsencrypt/live", // Let's Encrypt — high value
		"/etc/nginx/ssl",        // nginx common location
		"/etc/apache2/ssl",      // Apache common location
		"/etc/httpd/ssl",        // Apache RHEL
		"/etc/haproxy",          // HAProxy
		"/etc/dovecot/private",  // Dovecot mail
		"/etc/postfix/ssl",      // Postfix
	}
}

// scanCertPath walks path and parses any PEM certificate files.
func scanCertPath(root string, now time.Time) []models.CertInfo {
	var results []models.CertInfo

	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		// Only scan .pem, .crt, .cer files — skip .key, .csr, .conf
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".pem" && ext != ".crt" && ext != ".cer" && ext != ".cert" {
			return nil
		}
		certs := parseCertFile(path, now)
		results = append(results, certs...)
		return nil
	})
	return results
}

// expiryDays returns whole days from now until notAfter — positive while the
// cert is valid, negative once it has expired. int() truncates toward zero, so a
// cert that expired less than 24h ago divides to a fraction in (-1,0) and would
// round to 0 — misreported as "expires in 0 days" (about to break) instead of
// already-expired (down now), and mis-bucketed as Expiring rather than Expired.
// Force the sign negative for any cert whose NotAfter is already in the past.
func expiryDays(notAfter, now time.Time) int {
	days := int(notAfter.Sub(now).Hours() / 24)
	if days == 0 && notAfter.Before(now) {
		days = -1
	}
	return days
}

// parseCertFile reads a PEM file and extracts certificate expiry info.
func parseCertFile(path string, now time.Time) []models.CertInfo {
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- path from hardcoded list
	if err != nil {
		return nil
	}

	var results []models.CertInfo
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
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

		daysLeft := expiryDays(cert.NotAfter, now)
		selfSigned := cert.Issuer.String() == cert.Subject.String()

		// Skip root CA certs — they're long-lived and noise
		if selfSigned && daysLeft > 365 {
			continue
		}

		subject := cert.Subject.CommonName
		if subject == "" {
			subject = cert.Subject.String()
		}
		if len(subject) > 60 {
			subject = subject[:60] + "…"
		}

		results = append(results, models.CertInfo{
			Path:         path,
			Subject:      subject,
			Issuer:       cert.Issuer.CommonName,
			ExpiresIn:    daysLeft,
			NotAfter:     cert.NotAfter.Format("2006-01-02"),
			IsSelfSigned: selfSigned,
		})
	}
	return results
}
