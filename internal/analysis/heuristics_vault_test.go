package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckVault(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		v    models.VaultInfo
		want string
	}{
		{"not available is silent", models.VaultInfo{Available: false}, ""},
		{"not reachable is WARN", models.VaultInfo{Available: true, Reachable: false}, "WARN"},
		{"reachable but API unreadable is INFO", models.VaultInfo{Available: true, Reachable: true, StatusRead: false}, "INFO"},
		// HTTPStatus > 0 means the server responded but with non-Vault JSON (proxy, wrong port) → WARN.
		{"reachable, HTTPStatus set, StatusRead false is WARN", models.VaultInfo{Available: true, Reachable: true, StatusRead: false, HTTPStatus: 503}, "WARN"},
		{"reachable, HTTPStatus 200, StatusRead false is WARN", models.VaultInfo{Available: true, Reachable: true, StatusRead: false, HTTPStatus: 200}, "WARN"},
		{"healthy vault is clean", models.VaultInfo{
			Available: true, Reachable: true, StatusRead: true,
			Initialized: true, Sealed: false, DevMode: false, TLSEnabled: true,
		}, ""},
		{"dev mode is CRIT", models.VaultInfo{
			Available: true, Reachable: true, StatusRead: true,
			Initialized: true, Sealed: false, DevMode: true, TLSEnabled: false,
		}, "CRIT"},
		{"sealed is CRIT", models.VaultInfo{
			Available: true, Reachable: true, StatusRead: true,
			Initialized: true, Sealed: true, DevMode: false, TLSEnabled: true,
		}, "CRIT"},
		{"uninitialised is WARN", models.VaultInfo{
			Available: true, Reachable: true, StatusRead: true,
			Initialized: false, Sealed: false, DevMode: false, TLSEnabled: true,
		}, "WARN"},
		{"no TLS in prod mode is WARN", models.VaultInfo{
			Available: true, Reachable: true, StatusRead: true,
			Initialized: true, Sealed: false, DevMode: false, TLSEnabled: false,
		}, "WARN"},
		// Dev mode suppresses the TLS warning — dev implies inmem, not a misconfiguration.
		{"dev mode suppresses TLS warn", models.VaultInfo{
			Available: true, Reachable: true, StatusRead: true,
			Initialized: true, Sealed: false, DevMode: true, TLSEnabled: false,
		}, "CRIT"}, // CRIT from dev mode only, no duplicate TLS WARN
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertLevel(t, checkVault(tt.v), tt.want)
		})
	}
}

func TestCheckVaultProxyIntercept(t *testing.T) {
	t.Parallel()
	// HTTPStatus=503, StatusRead=false: load balancer returned HTML, not Vault JSON.
	// Must emit WARN with the HTTP status code in the finding text.
	insights := checkVault(models.VaultInfo{
		Available: true, Reachable: true, StatusRead: false, HTTPStatus: 503,
	})
	if len(insights) != 1 {
		t.Fatalf("expected 1 insight, got %d: %+v", len(insights), insights)
	}
	if insights[0].Level != "WARN" {
		t.Errorf("Level = %q, want WARN", insights[0].Level)
	}
	if !strings.Contains(insights[0].Message, "503") {
		t.Errorf("finding does not mention HTTP status 503: %q", insights[0].Message)
	}
}

func TestCheckVaultDevModeNoTLSWarn(t *testing.T) {
	t.Parallel()
	// When DevMode is true, there must be no TLS insight — dev mode is already CRIT.
	insights := checkVault(models.VaultInfo{
		Available: true, Reachable: true, StatusRead: true,
		Initialized: true, Sealed: false, DevMode: true, TLSEnabled: false,
	})
	for _, ins := range insights {
		if ins.Level == "WARN" {
			t.Errorf("unexpected WARN in dev mode (TLS warning should be suppressed): %+v", ins)
		}
	}
}
