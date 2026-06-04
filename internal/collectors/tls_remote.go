//go:build linux || darwin

package collectors

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// CheckRemoteEndpoint dials host:port over TLS, retrieves the peer certificate
// chain, and returns CertInfo for each cert (leaf first).
// Uses a 5-second dial+handshake timeout. Skips verification so expired certs
// are still readable (we want to *report* expired, not refuse to connect).
func CheckRemoteEndpoint(ctx context.Context, endpoint string) ([]models.CertInfo, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(dialCtx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()

	// Extract host for SNI (strip port)
	host, _, _ := net.SplitHostPort(endpoint)

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // #nosec G402 — intentional: report expired certs
	})
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := tlsConn.Handshake(); err != nil {
		// Handshake may fail for expired certs on strict servers — still try to
		// read the peer certs from the connection state.
		if len(tlsConn.ConnectionState().PeerCertificates) == 0 {
			return nil, err
		}
	}

	now := time.Now()
	var certs []models.CertInfo
	for _, cert := range tlsConn.ConnectionState().PeerCertificates {
		expiresIn := int(cert.NotAfter.Sub(now).Hours() / 24)
		certs = append(certs, models.CertInfo{
			Path:         endpoint, // use endpoint as "path" for display
			Subject:      cert.Subject.CommonName,
			Issuer:       cert.Issuer.CommonName,
			ExpiresIn:    expiresIn,
			NotAfter:     cert.NotAfter.Format("2006-01-02"),
			IsSelfSigned: cert.Subject.CommonName == cert.Issuer.CommonName,
		})
	}
	return certs, nil
}
