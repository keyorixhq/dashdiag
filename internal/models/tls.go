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
	Certs           []CertInfo `json:"certs"`
	Expiring        int        `json:"expiring"`                   // expiring within 30 days
	Expired         int        `json:"expired"`                    // already expired
	RemoteEndpoints []string   `json:"remote_endpoints,omitempty"` // endpoints that were checked
	// Uncheckable lists cert files / remote endpoints that could NOT be read
	// (e.g. an unreachable endpoint). Reported so a `0 expired` result is never
	// mistaken for "all healthy" when some certs were never actually checked.
	Uncheckable  []TLSUncheckable `json:"uncheckable,omitempty"`
	Status       string           `json:"status,omitempty"`
	StatusReason string           `json:"status_reason,omitempty"`
}

// TLSUncheckable is a cert path or remote endpoint that could not be evaluated.
type TLSUncheckable struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}
