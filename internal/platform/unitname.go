package platform

import "regexp"

var reUnitName = regexp.MustCompile(`^[A-Za-z0-9:_.\\@-]+$`)

// rootUnits are the only unit names that legitimately begin with '-': systemd
// escapes the path "/" as "-" (systemd.unit(5), "String escaping for
// inclusion in unit names"), so the root filesystem mount is "-.mount" and the
// root slice is "-.slice". Every call site places "--" before the unit, so
// these cannot be read as options.
var rootUnits = map[string]bool{"-.mount": true, "-.slice": true}

// ValidUnitName reports whether s is a conservative systemd unit name: only
// [A-Za-z0-9:_.\@-], at most 256 bytes, and no leading '-' (which a tool would
// parse as an option) except for the exact root units in rootUnits. Unit names
// read from the host must pass this before being handed to systemctl, always
// after a "--".
func ValidUnitName(s string) bool {
	if rootUnits[s] {
		return true
	}
	return s != "" && len(s) <= 256 && s[0] != '-' && reUnitName.MatchString(s)
}
