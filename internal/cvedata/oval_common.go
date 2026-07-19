//go:build linux

package cvedata

import "strings"

// ovalBuildResult finds which components from rec are installed and returns the
// OVALCVSSResult if any match. ok is false when no installed components match.
func ovalBuildResult(installed map[string]bool, rec RHELCVERecord) (OVALCVSSResult, bool) {
	var matches []string
	for _, comp := range rec.Components {
		if installed[strings.ToLower(comp)] {
			matches = append(matches, comp)
		}
	}
	if len(matches) == 0 {
		return OVALCVSSResult{}, false
	}
	return OVALCVSSResult{
		CVEID:      rec.CVEID,
		CVSS3:      rec.CVSS3,
		Severity:   rec.Severity,
		State:      rec.State,
		Components: rec.Components,
		Installed:  matches,
	}, true
}
