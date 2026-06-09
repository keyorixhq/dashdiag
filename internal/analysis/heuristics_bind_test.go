package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// A BIND server without dig installed (QueryTested=false) must NOT be reported as
// "named is not answering" — that's a false outage alarm. It should be an INFO
// that the check couldn't run. A real non-answering named (QueryTested=true,
// QueryOK=false) still fires CRIT.
func TestCheckBIND_QueryTestedGatesTheCrit(t *testing.T) {
	base := models.BINDInfo{Detected: true, ServiceActive: true, ConfigOK: true}

	t.Run("dig missing -> INFO, not CRIT", func(t *testing.T) {
		b := base // QueryTested=false, QueryOK=false
		ins := checkBIND(b)
		if hasInsight(ins, "CRIT", "not answering") {
			t.Errorf("must not CRIT 'not answering' when query was never tested: %+v", ins)
		}
		if !hasInsight(ins, "INFO", "could not verify") {
			t.Errorf("want INFO 'could not verify' when dig missing, got %+v", ins)
		}
	})

	t.Run("tested and not answering -> CRIT", func(t *testing.T) {
		b := base
		b.QueryTested = true
		b.QueryOK = false
		if !hasInsight(checkBIND(b), "CRIT", "not answering") {
			t.Error("want CRIT when query tested and named is not answering")
		}
	})

	t.Run("tested and answering -> no query insight", func(t *testing.T) {
		b := base
		b.QueryTested = true
		b.QueryOK = true
		ins := checkBIND(b)
		if hasInsight(ins, "CRIT", "not answering") || hasInsight(ins, "INFO", "could not verify") {
			t.Errorf("healthy BIND should emit no query insight, got %+v", ins)
		}
	})
}
