package render

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// A subsystem-qualified CRIT ("Network/DNS") must surface as a CRIT row for its
// collector ("Network") in the --report Check Results table. The table used to
// re-derive status from the raw insights keyed by the qualified Check name and
// look it up by the base collector name, so a DNS-only CRIT rendered "Network ✅ OK"
// even though the Issues section above listed the CRIT — a false-OK in the report.
func TestReport_QualifiedCheckCritShowsInTable(t *testing.T) {
	results := []runner.Result{
		{Name: "Network", Data: &models.NetworkInfo{}},
		{Name: "Memory", Data: &models.MemoryInfo{TotalGB: 1}},
	}
	insights := []models.Insight{
		{Check: "Network/DNS", Level: "CRIT", Message: "resolver unreachable"},
		// Memory: an earlier WARN then a worse CRIT for the same base check.
		{Check: "Memory", Level: "WARN", Message: "high usage"},
		{Check: "Memory/Slab", Level: "CRIT", Message: "slab leak"},
	}
	snap := baseline.BuildSnapshot(results, insights)

	md := buildMarkdown(snap, insights, time.Second, nil)

	tbl := md[strings.Index(md, "## Check Results"):]
	for _, want := range []string{
		"| Network | 🔴 CRIT |",
		"| Memory | 🔴 CRIT |",
	} {
		if !strings.Contains(tbl, want) {
			t.Errorf("Check Results table missing %q\n--- table ---\n%s", want, tbl)
		}
	}
	if strings.Contains(tbl, "| Network | ✅ OK |") {
		t.Errorf("Network rendered as OK despite a DNS CRIT (false-OK regression)\n%s", tbl)
	}
}
