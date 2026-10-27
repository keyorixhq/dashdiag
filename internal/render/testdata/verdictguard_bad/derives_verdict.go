// Package badverdict is the NEGATIVE EXAMPLE for TestGuardB_NoSecondVerdictDerivation:
// everything below is a second, private derivation of the overall verdict and the
// all-clear wording, exactly the shape DD-VERDICT-1 removed. The guard must flag
// every marked site. It lives in testdata, so it is never compiled.
package badverdict

import "github.com/keyorixhq/dashdiag/internal/models"

// GUARD-B-EXPECT: literal
const banner = "✅ System healthy. Checks passed"

// GUARD-B-EXPECT: literal
func plainLine() string { return "OK: All checks passed" }

// GUARD-B-EXPECT: literal
var htmlLabel = "HEALTHY"

// GUARD-B-EXPECT: func
func verdictOf(insights []models.Insight) string {
	v := "OK"
	for _, ins := range insights {
		switch ins.Level {
		case "CRIT":
			return "CRIT"
		case "WARN":
			v = "WARN"
		case "INFO":
		}
	}
	return v
}
