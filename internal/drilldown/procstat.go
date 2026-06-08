package drilldown

import "strings"

// parseProcStatComm splits a /proc/<pid>/stat line into the comm (process name,
// parens removed) and the whitespace-separated fields that FOLLOW the comm.
//
// The comm field (stat field 2) is wrapped in parens and may itself contain
// spaces and parens — the kernel does not escape them (e.g. "(Web Content)").
// So callers must NOT strings.Fields the whole line: the inner spaces shift
// every subsequent index, corrupting state/ppid/utime/stime reads. The comm is
// everything between the FIRST '(' and the LAST ')'.
//
// In the returned rest slice, index 0 is the state (stat field 3), so stat
// field N maps to rest[N-3]: state=rest[0], ppid=rest[1], utime=rest[11],
// stime=rest[12].
func parseProcStatComm(stat string) (name string, rest []string, ok bool) {
	open := strings.IndexByte(stat, '(')
	closeIdx := strings.LastIndexByte(stat, ')')
	if open < 0 || closeIdx < open {
		return "", nil, false
	}
	name = stat[open+1 : closeIdx]
	rest = strings.Fields(stat[closeIdx+1:])
	return name, rest, true
}
