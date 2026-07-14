package models

// VaultInfo captures the health of a local HashiCorp Vault instance.
// Populated from the unauthenticated endpoints /v1/sys/health and
// /v1/sys/seal-status. Secrets, policies, audit log state, and token TTLs
// require authentication and are surfaced platform-side, not here.
type VaultInfo struct {
	Available    bool   `json:"available"`              // gate passed: binary on PATH or :8200 is listening
	Reachable    bool   `json:"reachable"`              // TCP connect to :8200 succeeded
	StatusRead   bool   `json:"status_read"`            // API response parsed successfully
	Initialized  bool   `json:"initialized"`            // vault has been initialised (unseal keys distributed)
	Sealed       bool   `json:"sealed"`                 // vault is sealed — secrets unavailable
	DevMode      bool   `json:"dev_mode"`               // storage backend is "inmem": no persistence, no security
	TLSEnabled   bool   `json:"tls_enabled"`            // HTTPS accepted on :8200
	StorageType  string `json:"storage_type,omitempty"` // e.g. "raft", "file", "inmem"
	Version      string `json:"version,omitempty"`
	Status       string `json:"status"`
	StatusReason string `json:"status_reason,omitempty"`
}
