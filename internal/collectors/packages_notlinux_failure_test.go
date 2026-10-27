//go:build !linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// DD-COLLECTOR-GAPS-1 Low #22: a failed `brew outdated` must not leave Checked=true
// with 0 updates; it reports query-failed so the analysis layer says "could not
// verify".
func TestPackagesCollector_BrewFailureIsQueryFailed(t *testing.T) {
	b := source.NewBundle()
	b.PutStat("/opt/homebrew/bin/brew", source.FileMeta{Mode: 0o755})
	b.PutCmd("/opt/homebrew/bin/brew", []string{"outdated", "--quiet"}, "", 1)
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	raw, err := NewPackagesCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.PackagesInfo)
	if info.Checked || info.Status != "query-failed" || info.StatusReason == "" {
		t.Fatalf("info = %+v, want Checked=false Status=query-failed with a reason", info)
	}
}
