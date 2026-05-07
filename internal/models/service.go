package models

type ServiceResult struct {
	Name       string  `json:"name"`
	Host       string  `json:"host"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Reachable  bool    `json:"reachable"`
	LatencyMs  float64 `json:"latency_ms"`
	StatusCode int     `json:"status_code,omitempty"`
	Error      string  `json:"error,omitempty"`
	Status     string  `json:"status"`
}

type ServicesInfo struct {
	Results []ServiceResult `json:"results"`
	Status  string          `json:"status"`
}
