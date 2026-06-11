// Package explain holds the knowledge content behind `dsd explain <topic>` — a
// plain-language description of what each health check diagnoses, why it matters,
// how dsd decides severity, and how to investigate and fix it. It is static
// content: no host access, no collectors, so it can never produce a wrong verdict.
package explain

import (
	"sort"
	"strings"
)

// Topic is one explainable subsystem/check.
type Topic struct {
	Key     string   `json:"key"`
	Title   string   `json:"title"`
	Aliases []string `json:"aliases,omitempty"`
	Summary string   `json:"summary"`       // one line
	Checks  string   `json:"checks"`        // what dsd looks at
	Matters string   `json:"matters"`       // why it matters
	Verdict string   `json:"verdict"`       // how dsd assigns severity
	Look    []string `json:"investigate"`   // commands to investigate
	Fix     []string `json:"fix,omitempty"` // commands/steps to fix
}

// Lookup resolves a user query to a topic. It tries, in order: exact key, alias,
// then a unique prefix/substring match. The second return is the set of candidate
// keys when the query is ambiguous (more than one match) — empty on a clean hit.
func Lookup(query string) (*Topic, []string) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil, nil
	}
	for i := range topics {
		if topics[i].Key == q {
			return &topics[i], nil
		}
		for _, a := range topics[i].Aliases {
			if a == q {
				return &topics[i], nil
			}
		}
	}
	// Fuzzy: collect topics whose key/alias contains the query.
	var hits []int
	for i := range topics {
		if strings.Contains(topics[i].Key, q) || aliasContains(topics[i].Aliases, q) {
			hits = append(hits, i)
		}
	}
	if len(hits) == 1 {
		return &topics[hits[0]], nil
	}
	if len(hits) > 1 {
		cands := make([]string, 0, len(hits))
		for _, i := range hits {
			cands = append(cands, topics[i].Key)
		}
		sort.Strings(cands)
		return nil, cands
	}
	return nil, nil
}

func aliasContains(aliases []string, q string) bool {
	for _, a := range aliases {
		if strings.Contains(a, q) {
			return true
		}
	}
	return false
}

// Topics returns all topics sorted by key, for the index listing.
func Topics() []Topic {
	out := make([]Topic, len(topics))
	copy(out, topics)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
