package models

type SystemdInfo struct {
	Available    bool     `json:"available"`
	FailedUnits  []string `json:"failed_units"`
	StuckUnits   []string `json:"stuck_units"`
	Status       string   `json:"status"`
	StatusReason string   `json:"status_reason"`
}
