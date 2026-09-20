//go:build linux || darwin

package collectors

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// errTLSEndpointOffline is returned by CheckRemoteEndpoint when DSD_OFFLINE is
// set. `dsd tls --endpoint` is in cmd/root.go's networkFlagExempt list —
// naming the endpoint on the command line is itself the opt-in, so
// --network/DSD_ALLOW_NETWORK deliberately have no bearing here (see
// PRIVACY.md "Network calls") — but DSD_OFFLINE's hard "go offline no matter
// what" override must still be honored, the same as every other outbound call
// site in the repo (platform.OfflineForced). This was KV-TLS-OFFLINE-BYPASS:
// the only remote-dialing path that skipped this check.
var errTLSEndpointOffline = errors.New("network access disabled (DSD_OFFLINE=1) — dsd tls --endpoint requires network access")

// CheckRemoteEndpoint dials host:port over TLS, retrieves the peer certificate
// chain, and returns CertInfo for each cert (leaf first).
// Uses a 5-second dial+handshake timeout. Skips verification so expired certs
// are still readable (we want to *report* expired, not refuse to connect).
//
// Routed through the source so a `tls --endpoint` probe is recorded by capture and
// replayed from the bundle instead of dialing the replaying machine (which can't
// reach the captured host's endpoint). Each cert's ExpiresIn is computed at capture
// time and frozen in the recording, so replay reproduces the captured host's view;
// a recording gap surfaces as the dial error, never a live re-dial.
//
// The DSD_OFFLINE check is placed here, before the cachedJSON call, so a
// disallowed run never reaches the dial at all — the same placement
// cloudmeta_linux.go's imdsGet uses for its own gate. sourceIsReplaying short-
// circuits it so `dsd replay` still serves a bundle recorded before this fix
// existed, instead of fabricating an offline error over a captured result.
func CheckRemoteEndpoint(ctx context.Context, endpoint string) ([]models.CertInfo, error) {
	if platform.OfflineForced() && !sourceIsReplaying() {
		return nil, errTLSEndpointOffline
	}
	var certs []models.CertInfo
	if err := cachedJSON("tls-endpoint/"+endpoint, func() (any, error) {
		return checkRemoteEndpointLive(ctx, endpoint)
	}, &certs); err != nil {
		return nil, err
	}
	return certs, nil
}

func checkRemoteEndpointLive(ctx context.Context, endpoint string) ([]models.CertInfo, error) {
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

	tlsConn := tls.Client(rawConn, &tls.Config{ // NOSONAR nosemgrep: go.lang.security.audit.crypto.missing-ssl-minversion.missing-ssl-minversion — intentional: collector must connect to any TLS version to diagnose expired/invalid certs
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // G402: intentional: collector reads expired/invalid certs to diagnose them // codeql[go/disabled-certificate-check]
	})
	if err := tlsConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}

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
		expiresIn := expiryDays(cert.NotAfter, now)
		certs = append(certs, models.CertInfo{
			Path:         endpoint, // use endpoint as "path" for display
			Subject:      cert.Subject.CommonName,
			Issuer:       cert.Issuer.CommonName,
			ExpiresIn:    expiresIn,
			NotAfter:     cert.NotAfter.Format("2006-01-02"),
			IsSelfSigned: bytes.Equal(cert.RawSubject, cert.RawIssuer),
		})
	}
	return certs, nil
}
