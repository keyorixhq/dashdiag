package platform

import "regexp"

var reUnitName = regexp.MustCompile(`^[A-Za-z0-9:_.\\@-]+$`)

// ValidUnitName reports whether s is a conservative systemd unit name: only
// [A-Za-z0-9:_.\@-], at most 256 bytes, and never a leading '-' (which a tool
// would parse as an option). Unit names read from the host must pass this
// before being handed to systemctl.
func ValidUnitName(s string) bool {
	return s != "" && len(s) <= 256 && s[0] != '-' && reUnitName.MatchString(s)
}
