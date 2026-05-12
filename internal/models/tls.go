package models

// CertInfo holds expiry data for a single certificate file.
type CertInfo struct {
	Path         string `json:"path"`
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	ExpiresIn    int    `json:"expires_in_days"` // negative = already expired
	NotAfter     string `json:"not_after"`
	IsSelfSigned bool   `json:"self_signed"`
}

// TLSInfo holds all certificate findings.
type TLSInfo struct {
	Certs        []CertInfo `json:"certs"`
	Expiring     int        `json:"expiring"` // expiring within 30 days
	Expired      int        `json:"expired"`  // already expired
	Status       string     `json:"status,omitempty"`
	StatusReason string     `json:"status_reason,omitempty"`
}
