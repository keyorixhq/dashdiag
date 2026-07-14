//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
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
	cached := map[string][]byte{}

	if dialOk {
		cached["dial/tcp/127.0.0.1:8200"] = []byte{'1'}
	} else {
		cached["dial/tcp/127.0.0.1:8200"] = []byte{'0'}
	}

	if healthBody != "" {
		encoded, _ := json.Marshal(httpGetResult{Body: []byte(healthBody), Code: 200})
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
