package models

// CISStatus is the result of one CIS/STIG benchmark check.
type CISStatus string

const (
	CISPass          CISStatus = "PASS"
	CISFail          CISStatus = "FAIL"
	CISManual        CISStatus = "MANUAL" // requires human inspection
	CISNotApplicable CISStatus = "N/A"
	CISSkipped       CISStatus = "SKIP" // prerequisite not met (e.g. service not installed)
)

// CISResult is one evaluated benchmark rule.
type CISResult struct {
	ID          string    `json:"id"`          // e.g. "5.2.7" or "V-238201"
	Framework   string    `json:"framework"`   // "CIS" or "STIG"
	Level       int       `json:"level"`       // 1 = basic, 2 = advanced
	Section     string    `json:"section"`     // human-readable category
	Description string    `json:"description"` // what the rule checks
	Status      CISStatus `json:"status"`
	Finding     string    `json:"finding,omitempty"`     // what was actually found
	Remediation string    `json:"remediation,omitempty"` // how to fix it
}

// CISReport is the full output of a compliance scan.
type CISReport struct {
	Framework string      `json:"framework"` // CIS or STIG
	Profile   string      `json:"profile"`   // e.g. "Ubuntu 22.04 LTS Level 1"
	OS        string      `json:"os"`
	Hostname  string      `json:"hostname"`
	Results   []CISResult `json:"results"`
	Pass      int         `json:"pass"`
	Fail      int         `json:"fail"`
	Manual    int         `json:"manual"`
	NA        int         `json:"not_applicable"`
	Skipped   int         `json:"skipped"`
}
