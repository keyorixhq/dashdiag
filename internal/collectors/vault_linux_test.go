//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// seedVaultFixture installs a fakeCombinedFixture with a controlled dial
// outcome and optional pre-seeded HTTP responses for the vault API endpoints.
// healthBody / sealBody may be empty to simulate a missing/failed HTTP probe.
// Pass an invalid JSON string to get a parse failure with a reachable port.
//
// NOTE: these tests must NOT call t.Parallel() — withCombinedFixture mutates
// the global active source via SetSource and parallel tests would race.
func seedVaultFixture(t *testing.T, dialOk bool, healthBody, sealBody string) {
	t.Helper()
	seedVaultFixtureWithCode(t, dialOk, healthBody, 200, sealBody)
}

// seedVaultFixtureWithCode is like seedVaultFixture but allows specifying the
// HTTP status code for the health endpoint (e.g. 503 for a proxy error page).
func seedVaultFixtureWithCode(t *testing.T, dialOk bool, healthBody string, healthCode int, sealBody string) {
	t.Helper()
	cached := map[string][]byte{}

	if dialOk {
		cached["dial/tcp/127.0.0.1:8200"] = []byte{'1'}
	} else {
		cached["dial/tcp/127.0.0.1:8200"] = []byte{'0'}
	}

	if healthBody != "" {
		encoded, _ := json.Marshal(httpGetResult{Body: []byte(healthBody), Code: healthCode})
		cached["http/https://127.0.0.1:8200/v1/sys/health"] = encoded
	}
	if sealBody != "" {
		encoded, _ := json.Marshal(httpGetResult{Body: []byte(sealBody), Code: 200})
		cached["http/https://127.0.0.1:8200/v1/sys/seal-status"] = encoded
	}

	withCombinedFixture(t, cached, nil, nil)
}

func TestVaultCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewVaultCollector()
	if c.Name() != "Vault" {
		t.Errorf("Name() = %q, want Vault", c.Name())
	}
	if c.Timeout() != 8*time.Second {
		t.Errorf("Timeout() = %v, want 8s", c.Timeout())
	}
}

func TestVaultAvailable_NotReachable(t *testing.T) {
	// Omit lookpath/vault entirely: missing key → Cached returns errNotFoundCVE
	// → lookPath returns error → VaultAvailable false.
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:8200": {'0'},
	}, nil, nil)
	if VaultAvailable() {
		t.Error("VaultAvailable() = true, want false when port closed and binary absent")
	}
}

func TestVaultAvailable_DialOK(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:8200": {'1'},
	}, nil, nil)
	if !VaultAvailable() {
		t.Error("VaultAvailable() = false, want true when port open")
	}
}

func TestVaultCollect_NotReachable(t *testing.T) {
	seedVaultFixture(t, false, "", "")

	raw, err := NewVaultCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VaultInfo)
	if !info.Available {
		t.Error("Available should be true — collector is always called with Available=true")
	}
	if info.Reachable {
		t.Error("Reachable = true, want false when dial fails")
	}
}

// TestVaultCollect_ReachableAPIFails: dial OK and port returns a response, but
// the body is not valid vault JSON — vaultProbeBase returns a base URL
// (Reachable=true) but vaultFetchHealth cannot parse it (StatusRead=false).
func TestVaultCollect_ReachableAPIFails(t *testing.T) {
	seedVaultFixture(t, true, "not-json", "")

	raw, err := NewVaultCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VaultInfo)
	if !info.Reachable {
		t.Error("Reachable = false, want true when port responds")
	}
	if info.StatusRead {
		t.Error("StatusRead = true, want false when body is not valid vault JSON")
	}
	// HTTP status must be captured even when the body was unparseable.
	if info.HTTPStatus != 200 {
		t.Errorf("HTTPStatus = %d, want 200", info.HTTPStatus)
	}
}

// TestVaultCollect_ProxyIntercept503: a load balancer returns HTTP 503 with an
// HTML body. The collector must set HTTPStatus=503 and leave StatusRead=false so
// the analysis layer can emit WARN instead of INFO.
func TestVaultCollect_ProxyIntercept503(t *testing.T) {
	seedVaultFixtureWithCode(t, true, "<html>503 Service Unavailable</html>", 503, "")

	raw, err := NewVaultCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VaultInfo)
	if !info.Reachable {
		t.Error("Reachable = false, want true when port responds")
	}
	if info.StatusRead {
		t.Error("StatusRead = true, want false when body is HTML not Vault JSON")
	}
	if info.HTTPStatus != 503 {
		t.Errorf("HTTPStatus = %d, want 503", info.HTTPStatus)
	}
}

// TestVaultCollect_HTTPStatusOnSuccess: a healthy Vault response must populate
// HTTPStatus with the actual HTTP code (200 for active, but Vault also uses
// 429/501/503 for standby/uninitialised/sealed — the status code is always set).
func TestVaultCollect_HTTPStatusOnSuccess(t *testing.T) {
	health := `{"initialized":true,"sealed":false,"version":"1.15.0"}`
	seedVaultFixture(t, true, health, "")

	raw, err := NewVaultCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VaultInfo)
	if !info.StatusRead {
		t.Error("StatusRead = false, want true for valid Vault JSON")
	}
	if info.HTTPStatus != 200 {
		t.Errorf("HTTPStatus = %d, want 200", info.HTTPStatus)
	}
}

func TestVaultCollect_HealthyRaft(t *testing.T) {
	health := `{"initialized":true,"sealed":false,"version":"1.15.0"}`
	seal := `{"storage_type":"raft"}`
	seedVaultFixture(t, true, health, seal)

	raw, err := NewVaultCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VaultInfo)
	if !info.Reachable || !info.StatusRead {
		t.Errorf("expected reachable+read, got %+v", info)
	}
	if !info.Initialized || info.Sealed {
		t.Errorf("unexpected initialized/sealed state: %+v", info)
	}
	if info.DevMode {
		t.Error("DevMode = true, want false for raft storage")
	}
	if !info.TLSEnabled {
		t.Errorf("TLSEnabled = false, want true (HTTPS probe succeeded)")
	}
	if info.StorageType != "raft" {
		t.Errorf("StorageType = %q, want raft", info.StorageType)
	}
	if info.Version != "1.15.0" {
		t.Errorf("Version = %q, want 1.15.0", info.Version)
	}
}

func TestVaultCollect_DevMode(t *testing.T) {
	health := `{"initialized":true,"sealed":false,"version":"1.15.0"}`
	seal := `{"storage_type":"inmem"}`
	seedVaultFixture(t, true, health, seal)

	raw, err := NewVaultCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VaultInfo)
	if !info.DevMode {
		t.Error("DevMode = false, want true for inmem storage")
	}
	if info.StorageType != "inmem" {
		t.Errorf("StorageType = %q, want inmem", info.StorageType)
	}
}

func TestVaultCollect_Sealed(t *testing.T) {
	health := `{"initialized":true,"sealed":true,"version":"1.15.0"}`
	seal := `{"storage_type":"raft"}`
	seedVaultFixture(t, true, health, seal)

	raw, err := NewVaultCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VaultInfo)
	if !info.Sealed {
		t.Error("Sealed = false, want true")
	}
}

// TestVaultCollect_VersionAndStorageTypeSanitizedAndCapped is the regression
// test for internal-collectors-33-06: Version/StorageType never reach
// Insight.Message, so they must be both sanitized and length-capped at the
// point of assignment.
func TestVaultCollect_VersionAndStorageTypeSanitizedAndCapped(t *testing.T) {
	esc := string(rune(27))
	longVersion := "1.15.0" + esc + "[31m"
	longStorage := "raft" + esc + "[0m"
	for i := 0; i < 300; i++ {
		longVersion += "x"
		longStorage += "y"
	}
	health, err := json.Marshal(struct {
		Initialized bool   `json:"initialized"`
		Sealed      bool   `json:"sealed"`
		Version     string `json:"version"`
	}{Initialized: true, Sealed: false, Version: longVersion})
	if err != nil {
		t.Fatalf("json.Marshal(health): %v", err)
	}
	seal, err := json.Marshal(struct {
		StorageType string `json:"storage_type"`
	}{StorageType: longStorage})
	if err != nil {
		t.Fatalf("json.Marshal(seal): %v", err)
	}
	seedVaultFixture(t, true, string(health), string(seal))

	raw, err := NewVaultCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VaultInfo)
	if strings.Contains(info.Version, esc) {
		t.Errorf("Version = %q, want ESC stripped", info.Version)
	}
	if len([]rune(info.Version)) != 201 {
		t.Errorf("Version rune length = %d, want 201 (200 + ellipsis)", len([]rune(info.Version)))
	}
	if strings.Contains(info.StorageType, esc) {
		t.Errorf("StorageType = %q, want ESC stripped", info.StorageType)
	}
	if len([]rune(info.StorageType)) != 201 {
		t.Errorf("StorageType rune length = %d, want 201 (200 + ellipsis)", len([]rune(info.StorageType)))
	}
	if info.DevMode {
		t.Error("DevMode = true, want false — sanitized/capped storage type is not exactly \"inmem\"")
	}
}

// TestVaultCollect_IdentityUnverified_NoSS is the regression test for
// internal-collectors-33-05: when the listener's own identity can't be
// confirmed (here, ss is unavailable), IdentityUnverified must be true even
// though the health/seal-status responses parsed as valid Vault JSON.
func TestVaultCollect_IdentityUnverified_NoSS(t *testing.T) {
	health := `{"initialized":true,"sealed":false,"version":"1.15.0"}`
	seal := `{"storage_type":"raft"}`
	seedVaultFixture(t, true, health, seal) // no PutCmd for ss — command errors as not-recorded

	raw, err := NewVaultCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VaultInfo)
	if !info.IdentityUnverified {
		t.Error("IdentityUnverified = false, want true when ss is unavailable")
	}
}

// TestVaultCollect_IdentityVerified confirms IdentityUnverified is false when
// ss+cmdline confirm a real vault process.
func TestVaultCollect_IdentityVerified(t *testing.T) {
	health := `{"initialized":true,"sealed":false,"version":"1.15.0"}`
	seal := `{"storage_type":"raft"}`
	healthEnc, _ := json.Marshal(httpGetResult{Body: []byte(health), Code: 200})
	sealEnc, _ := json.Marshal(httpGetResult{Body: []byte(seal), Code: 200})
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:8200":                        {'1'},
		"http/https://127.0.0.1:8200/v1/sys/health":      healthEnc,
		"http/https://127.0.0.1:8200/v1/sys/seal-status": sealEnc,
	}, nil, func(b *source.Bundle) {
		b.PutCmd("ss", []string{"-tlnp"}, "LISTEN 0 128 127.0.0.1:8200 0.0.0.0:* users:((\"vault\",pid=999,fd=6))\n", 0)
		b.PutFile("/proc/999/cmdline", []byte("/usr/bin/vault\x00server\x00-config=/etc/vault.d/vault.hcl\x00"))
	})

	raw, err := NewVaultCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VaultInfo)
	if info.IdentityUnverified {
		t.Error("IdentityUnverified = true, want false when ss+cmdline confirm a real vault process")
	}
}
