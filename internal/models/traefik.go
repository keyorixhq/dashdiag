package models

// TraefikInfo holds guest-side health for a local Traefik proxy. Gated on the API
// (commonly :8080 with api.insecure, or a configured endpoint) answering as Traefik.
// The headline signal is routers in ERROR: Traefik disables a router whose rule,
// service, or middleware doesn't resolve, so that route silently stops being served
// (404/502 for that host/path) while the rest of the proxy keeps working. Reading
// the API needs it enabled; when it can't be read, APIRead stays false — never a
// false green.
type TraefikInfo struct {
	Detected bool   `json:"detected"`
	Version  string `json:"version,omitempty"`

	APIRead          bool `json:"api_read"`
	RoutersTotal     int  `json:"routers_total,omitempty"`
	RoutersErrors    int  `json:"routers_errors,omitempty"`
	RoutersWarnings  int  `json:"routers_warnings,omitempty"`
	ServicesErrors   int  `json:"services_errors,omitempty"`
	MiddlewareErrors int  `json:"middleware_errors,omitempty"`

	StatusReason string `json:"status_reason,omitempty"`
}
