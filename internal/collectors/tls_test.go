package collectors

import (
	"encoding/pem"
	"runtime"
	"slices"
	"testing"
	"time"
)

// expiryDays must report any already-expired cert as a negative number of days,
// including one that expired less than 24h ago. int() truncation toward zero
// would otherwise round -0.x to 0, mis-classifying a down cert as "expires in 0
// days" (Expiring) instead of expired (Expired/CRIT-now).
func TestExpiryDays(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		notAfter time.Time
		want     int
	}{
		{"valid 90 days", now.Add(90 * 24 * time.Hour), 90},
		{"valid 29.5 days floors to 29", now.Add(29*24*time.Hour + 12*time.Hour), 29},
		{"expires in 6h -> 0 (still valid)", now.Add(6 * time.Hour), 0},
		{"expired 1h ago -> negative (the bug)", now.Add(-1 * time.Hour), -1},
		{"expired 23h ago -> negative (the bug)", now.Add(-23 * time.Hour), -1},
		{"expired 2 days ago", now.Add(-2 * 24 * time.Hour), -2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := expiryDays(tc.notAfter, now); got != tc.want {
				t.Errorf("expiryDays = %d, want %d", got, tc.want)
			}
		})
	}
}

// The classification an expired-<24h cert must land in: ExpiresIn < 0 (Expired),
// never the >=0 Expiring bucket. Guards the integration with the collector's
// Expired/Expiring tally and the CRIT "expired N days ago" insight.
func TestExpiryDays_FreshlyExpiredIsNegative(t *testing.T) {
	now := time.Now()
	if d := expiryDays(now.Add(-time.Minute), now); d >= 0 {
		t.Errorf("a cert expired a minute ago must be negative, got %d", d)
	}
}

// TestParseCertFileUncheckable verifies the false-OK fix: a file with a garbled
// CERTIFICATE block is reported as Uncheckable, never silently dropped.
func TestParseCertFileUncheckable(t *testing.T) {
	dir := t.TempDir()
	garbled := dir + "/bad.crt"
	if err := osWriteFile(garbled, "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n"); err != nil {
		t.Fatal(err)
	}
	certs, unc := parseCertFile(garbled, time.Now())
	if len(certs) != 0 {
		t.Errorf("garbled cert should yield no parsed certs, got %d", len(certs))
	}
	if len(unc) != 1 {
		t.Fatalf("garbled CERTIFICATE block must be Uncheckable, got %d", len(unc))
	}
}

// TestParseCertFileNotYetValid verifies a cert whose NotBefore is in the future
// is flagged NotYetValid (would otherwise read healthy on its far-off expiry).
func TestParseCertFileNotYetValid(t *testing.T) {
	now := time.Now()
	// Valid from +2 days, expires +100 days (short enough to dodge the >365d root skip).
	pemBytes := makeTestCertPEM(t, now.Add(48*time.Hour), now.Add(100*24*time.Hour))
	dir := t.TempDir()
	p := dir + "/future.crt"
	if err := osWriteFileBytes(p, pemBytes); err != nil {
		t.Fatal(err)
	}
	certs, unc := parseCertFile(p, now)
	if len(unc) != 0 {
		t.Fatalf("valid PEM should not be uncheckable, got %v", unc)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if !certs[0].NotYetValid {
		t.Error("cert with future NotBefore must be NotYetValid")
	}
}

// TestScanCertPath_RecursesAndFilters is a regression guard for the switch from
// raw filepath.WalkDir to the Source-routed walkCertDir: recursion into
// subdirectories and the .pem/.crt/.cer/.cert extension filter must both still
// work identically.
func TestScanCertPath_RecursesAndFilters(t *testing.T) {
	now := time.Now()
	pemBytes := makeTestCertPEM(t, now.Add(-24*time.Hour), now.Add(100*24*time.Hour))

	root := t.TempDir()
	sub := root + "/nested"
	if err := osMkdirAll(sub); err != nil {
		t.Fatal(err)
	}
	if err := osWriteFileBytes(root+"/top.crt", pemBytes); err != nil {
		t.Fatal(err)
	}
	if err := osWriteFileBytes(sub+"/leaf.pem", pemBytes); err != nil {
		t.Fatal(err)
	}
	// A non-cert extension in the same directories must be skipped.
	if err := osWriteFile(sub+"/leaf.key", "not a cert"); err != nil {
		t.Fatal(err)
	}

	certs, unc := scanCertPath(root, now)
	if len(unc) != 0 {
		t.Fatalf("expected no uncheckable files, got %v", unc)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs (root + nested), got %d", len(certs))
	}
}

// TestTLSCertPaths_IncludesRHUI is a regression guard for the RHUI client-cert
// expiry check (Gap Spec R2): RHEL cloud PAYG images authenticate to the RHUI
// CDS mirrors via mTLS using /etc/pki/rhui/product/*.crt (sslclientcert in
// /etc/yum.repos.d/redhat-rhui*.repo). Confirmed live on an AWS EC2 RHEL 10.2
// box — those cert files are root-only (0600), so a non-root scan must report
// them as Uncheckable (never a silent "0 expired" false-OK), same as any other
// permission-gated path already in this list.
// TestParseCertFile_UnreadableFile guards the readFile error branch: an
// unreadable/missing path must report a single Uncheckable entry carrying the
// read error, never silently return an empty (clean-looking) result.
func TestParseCertFile_UnreadableFile(t *testing.T) {
	certs, unc := parseCertFile("/nonexistent/does-not-exist.crt", time.Now())
	if len(certs) != 0 {
		t.Errorf("expected no certs for an unreadable path, got %d", len(certs))
	}
	if len(unc) != 1 || unc[0].Path != "/nonexistent/does-not-exist.crt" || unc[0].Error == "" {
		t.Fatalf("expected 1 Uncheckable entry with a non-empty error, got %+v", unc)
	}
}

// TestParseCertFile_SkipsLongLivedSelfSignedRoot guards the root-CA noise
// filter: a self-signed cert (Issuer == Subject, via makeTestCertPEM) with
// more than 365 days left must be skipped entirely — neither counted as a
// cert nor flagged Uncheckable — since long-lived self-signed roots are
// expected and not actionable.
func TestParseCertFile_SkipsLongLivedSelfSignedRoot(t *testing.T) {
	now := time.Now()
	pemBytes := makeTestCertPEM(t, now.Add(-24*time.Hour), now.Add(400*24*time.Hour))
	dir := t.TempDir()
	p := dir + "/root-ca.crt"
	if err := osWriteFileBytes(p, pemBytes); err != nil {
		t.Fatal(err)
	}
	certs, unc := parseCertFile(p, now)
	if len(certs) != 0 || len(unc) != 0 {
		t.Errorf("expected a long-lived self-signed root to be silently skipped, got certs=%+v uncheckable=%+v", certs, unc)
	}
}

// TestParseCertFile_SkipsNonCertificatePEMBlock guards the block.Type filter:
// a PEM file with a non-"CERTIFICATE" block (e.g. a private key sitting
// alongside certs in /etc/ssl/private) must be skipped without error, and a
// genuine certificate block later in the same file must still be parsed.
func TestParseCertFile_SkipsNonCertificatePEMBlock(t *testing.T) {
	now := time.Now()
	certPEM := makeTestCertPEM(t, now.Add(-24*time.Hour), now.Add(100*24*time.Hour))
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a real key, just needs a non-CERTIFICATE type")})

	dir := t.TempDir()
	p := dir + "/combined.pem"
	combined := append(append([]byte{}, keyBlock...), certPEM...)
	if err := osWriteFileBytes(p, combined); err != nil {
		t.Fatal(err)
	}
	certs, unc := parseCertFile(p, now)
	if len(unc) != 0 {
		t.Errorf("a non-CERTIFICATE block must not be Uncheckable, got %+v", unc)
	}
	if len(certs) != 1 {
		t.Fatalf("expected the trailing CERTIFICATE block to still be parsed, got %d certs", len(certs))
	}
}

func TestTLSCertPaths_IncludesRHUI(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("RHUI is a RHEL-only path, not scanned on darwin")
	}
	if !slices.Contains(tlsCertPaths(), "/etc/pki/rhui") {
		t.Fatal("tlsCertPaths() must include /etc/pki/rhui for RHEL cloud PAYG client-cert expiry checks")
	}
}
