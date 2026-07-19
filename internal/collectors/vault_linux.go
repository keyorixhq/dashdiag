//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const vaultAddr = "127.0.0.1:8200"

// VaultAvailable reports whether Vault is expected on this host: port 8200 is
// accepting connections OR the vault binary is on PATH.
func VaultAvailable() bool {
	if dialReachable("tcp", vaultAddr, 300*time.Millisecond) {
		return true
	}
	_, err := lookPath("vault")
	return err == nil
}

type VaultCollector struct{}

func NewVaultCollector() *VaultCollector { return &VaultCollector{} }

func (c *VaultCollector) Name() string           { return "Vault" }
func (c *VaultCollector) Timeout() time.Duration { return 8 * time.Second }

func (c *VaultCollector) Collect(ctx context.Context) (any, error) {
	info := &models.VaultInfo{Available: true}

	// Probe HTTPS first, fall back to HTTP. Returns "" when :8200 is not reachable.
	base := vaultProbeBase(ctx, info)
	if base == "" {
		return info, nil
	}
	info.Reachable = true

	// /v1/sys/health: initialized, sealed, version. Vault uses non-200 status codes
	// to signal state (200=active, 429=standby, 503=sealed, 501=uninitialised) —
	// parse body regardless of code.
	vaultFetchHealth(ctx, base, info)

	// /v1/sys/seal-status: storage_type "inmem" == dev mode, no persistence.
	vaultFetchSealStatus(ctx, base, info)

	return info, nil
}

// vaultProbeBase tries HTTPS then HTTP on :8200. Sets info.TLSEnabled.
// Returns "" when the port is not reachable.
func vaultProbeBase(ctx context.Context, info *models.VaultInfo) string {
	if !dialReachable("tcp", vaultAddr, 300*time.Millisecond) {
		return ""
	}
	for _, scheme := range []string{"https", "http"} {
		body, _, err := httpGetCached(ctx, scheme+"://"+vaultAddr+"/v1/sys/health")
		if err != nil || len(body) == 0 {
			continue
		}
		if scheme == "https" {
			info.TLSEnabled = true
		}
		return scheme + "://" + vaultAddr
	}
	return ""
}

func vaultFetchHealth(ctx context.Context, base string, info *models.VaultInfo) {
	body, statusCode, err := httpGetCached(ctx, base+"/v1/sys/health")
	if err != nil || len(body) == 0 {
		return
	}
	// Record the HTTP status regardless of whether the body parses. A non-zero
	// code means the server responded; analysis uses this to distinguish
	// "unreachable" from "wrong/proxied response".
	info.HTTPStatus = statusCode
	var h struct {
		Initialized bool   `json:"initialized"`
		Sealed      bool   `json:"sealed"`
		Version     string `json:"version"`
	}
	if json.Unmarshal(body, &h) != nil {
		// Body arrived but was not valid Vault JSON — proxy page, wrong port, etc.
		// Leave StatusRead=false so analysis can emit WARN instead of INFO.
		return
	}
	info.StatusRead = true
	info.Initialized = h.Initialized
	info.Sealed = h.Sealed
	info.Version = h.Version
}

func vaultFetchSealStatus(ctx context.Context, base string, info *models.VaultInfo) {
	body, _, err := httpGetCached(ctx, base+"/v1/sys/seal-status")
	if err != nil || len(body) == 0 {
		return
	}
	var s struct {
		StorageType string `json:"storage_type"`
	}
	if json.Unmarshal(body, &s) != nil {
		return
	}
	info.StorageType = s.StorageType
	info.DevMode = s.StorageType == "inmem"
}
