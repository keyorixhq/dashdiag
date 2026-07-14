//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// seedVault builds a fakeCombinedFixture with a reachable vault port and
// optional health/seal-status responses seeded in the HTTP cache.
func seedVaultFixture(t *testing.T, dialOk bool, healthBody, sealBody string) {
	t.Helper()
	cached := map[string][]byte{}

	if dialOk {
		cached["dial/tcp/127.0.0.1:8200"] = []byte{'1'}
	} else {
		cached["dial/tcp/127.0.0.1:8200"] = []byte{'0'}
	}

	// HTTPS probe in vaultProbeBase and vaultFetchHealth both call the same URL.
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
	t.Parallel()
	// Neither port 8200 nor vault binary present.
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:8200": {'0'},
		"lookpath/vault":          nil, // nil → Cached returns error → lookPath returns error
	}, nil, nil)
	if VaultAvailable() {
		t.Error("VaultAvailable() = true, want false when port closed and binary absent")
	}
}

func TestVaultAvailable_DialOK(t *testing.T) {
	t.Parallel()
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:8200": {'1'},
	}, nil, nil)
	if !VaultAvailable() {
		t.Error("VaultAvailable() = false, want true when port open")
	}
}

func TestVaultCollect_NotReachable(t *testing.T) {
	t.Parallel()
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

func TestVaultCollect_ReachableAPIFails(t *testing.T) {
	t.Parallel()
	// Port accepts connections but /v1/sys/health returns nothing → StatusRead=false.
	seedVaultFixture(t, true, "", "")

	raw, err := NewVaultCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VaultInfo)
	if !info.Reachable {
		t.Error("Reachable = false, want true when dial OK")
	}
	if info.StatusRead {
		t.Error("StatusRead = true, want false when API body is absent")
	}
}

func TestVaultCollect_HealthyRaft(t *testing.T) {
	t.Parallel()
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
	if info.TLSEnabled != true {
		t.Errorf("TLSEnabled = %v, want true (HTTPS probe succeeded)", info.TLSEnabled)
	}
	if info.StorageType != "raft" {
		t.Errorf("StorageType = %q, want raft", info.StorageType)
	}
	if info.Version != "1.15.0" {
		t.Errorf("Version = %q, want 1.15.0", info.Version)
	}
}

func TestVaultCollect_DevMode(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
