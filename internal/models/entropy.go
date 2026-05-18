package models

// EntropyInfo holds kernel entropy pool data.
// Available is false on platforms without a software entropy pool (macOS).
type EntropyInfo struct {
	Available    bool   `json:"available"`         // false on non-Linux platforms
	EntropyBits  int    `json:"entropy_available"` // bits available in pool
	PoolSize     int    `json:"pool_size"`
	Status       string `json:"status,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
}
