package store

import "sort"

// CheckChange is one per-check status transition between two stored entries.
type CheckChange struct {
	Name   string `json:"name"`
	Before string `json:"before"` // empty = check first appeared in After
	After  string `json:"after"`  // empty = check was removed
}

// DiffChecks returns the checks whose status changed between prev and cur,
// sorted by name. New checks (present only in cur) have Before=""; removed
// checks (only in prev) have After="".
func DiffChecks(prev, cur Entry) []CheckChange {
	var out []CheckChange
	for name, after := range cur.Checks {
		if before := prev.Checks[name]; before != after {
			out = append(out, CheckChange{Name: name, Before: before, After: after})
		}
	}
	for name, before := range prev.Checks {
		if _, ok := cur.Checks[name]; !ok {
			out = append(out, CheckChange{Name: name, Before: before, After: ""})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
