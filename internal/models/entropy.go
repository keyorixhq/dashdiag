package models

// EntropyInfo holds kernel entropy pool data.
type EntropyInfo struct {
	Available    int    `json:"entropy_available"`
	PoolSize     int    `json:"pool_size"`
	Status       string `json:"status,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
}
