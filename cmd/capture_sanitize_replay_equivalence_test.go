package cmd

// capture_sanitize_replay_equivalence_test.go — the test GAP-2
// (docs/product-claim-gaps-2026-09-02.md) required before `dsd capture --raw`
// could safely default --sanitize to true: capture a real bundle, sanitize an
// independent copy of it, replay BOTH, and diff the resulting verdicts.
//
// dsd sanitize's own doc comment already claims "Redaction is deterministic,
// so the sanitized bundle still replays to the same verdicts" — this test
// proves that rather than trusting the comment. The open risk named in the
// gap doc: a collector or parser asserting on a VALUE that redaction masks,
// so a sanitized bundle replays differently from the raw one.
//
// On linux, a synthetic PVE auth-file fixture is injected into the bundle
// before saving, so the test exercises a REAL collision: pve_linux.go's
// collectPVESubscriptionFile() decides its verdict via
// strings.Contains(data, "login"), and sanitize.go's netrc-style rule
// redacts only the password VALUE on that exact line, deliberately keeping
// "login" intact — this is the regression guard for that contract. Without
// this injection, a bundle captured from a plain dev/CI box carries no
// credential-shaped content at all, and the equivalence check would pass
// trivially without proving anything.

import (
	"context"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
	"github.com/keyorixhq/dashdiag/internal/version"
)

func TestSanitizeReplayEquivalence(t *testing.T) {
	rec := source.NewRecorder(collectors.ActiveSource())
	prev := collectors.SetSource(rec)
	ctrCtx := platform.DetectContainerContext()
	cloudEnv := platform.DetectCloudEnvironment()
	profile := platform.Detect()
	_, _, _, _ = runHealthOnce(context.Background(), ctrCtx, cloudEnv, profile,
		output.ModePlain, healthRunOpts{Terse: true}, nil)
	collectors.SetSource(prev)

	raw := rec.Bundle()
	raw.Manifest = source.Manifest{
		Format:     source.FormatVersion,
		Host:       hostnameOr("host"),
		OS:         osPretty(),
		GOOS:       runtime.GOOS,
		InitSystem: profile.InitSystem,
		Kernel:     kernelRelease(),
		DsdVer:     version.Version,
		Created:    time.Now().UTC().Format(time.RFC3339),
		Note:       "TestSanitizeReplayEquivalence",
	}

	// linux-only: force a genuine credential-shaped redaction through a real
	// collector's real read path (see file header). IsPVEHost()/PVECollector
	// exist cross-platform (pve_notlinux.go stubs IsPVEHost to false), so this
	// injection is inert-but-harmless on darwin — it just proves nothing there.
	const pveConfPath = "/etc/apt/auth.conf.d/pve.conf"
	const netrcLine = "machine enterprise.proxmox.com login user@example.com password CANARY-SECRET-VALUE-12345\n"
	if runtime.GOOS == "linux" {
		raw.PutStat("/usr/bin/pvedaemon", source.FileMeta{Mode: 0o755})
		raw.PutFile(pveConfPath, []byte(netrcLine))
	}

	dir := t.TempDir()
	rawPath := filepath.Join(dir, "raw.tar.gz")
	if err := raw.SaveTarball(rawPath); err != nil {
		t.Fatalf("saving raw bundle: %v", err)
	}

	toSanitize, err := loadBundle(rawPath)
	if err != nil {
		t.Fatalf("loading bundle to sanitize: %v", err)
	}
	rep := toSanitize.Sanitize(source.SanitizeOptions{})
	t.Logf("sanitize report: %+v", rep)
	if runtime.GOOS == "linux" && rep.TotalRedactions == 0 {
		t.Fatal("expected the injected PVE auth-file credential to be redacted, but TotalRedactions == 0 — this test proves nothing without it")
	}
	sanPath := filepath.Join(dir, "sanitized.tar.gz")
	if err := toSanitize.SaveTarball(sanPath); err != nil {
		t.Fatalf("saving sanitized bundle: %v", err)
	}

	rawB, err := loadBundle(rawPath)
	if err != nil {
		t.Fatalf("loading raw bundle for replay: %v", err)
	}
	_, rawInsights, _ := replayBundle(rawB, false, false, false, false)

	sanB, err := loadBundle(sanPath)
	if err != nil {
		t.Fatalf("loading sanitized bundle for replay: %v", err)
	}
	_, sanInsights, _ := replayBundle(sanB, false, false, false, false)

	rawPairs := sortedCheckLevelPairs(rawInsights)
	sanPairs := sortedCheckLevelPairs(sanInsights)

	if len(rawPairs) != len(sanPairs) {
		t.Fatalf("sanitized bundle replays a different NUMBER of insights than raw:\nraw:       %v\nsanitized: %v", rawPairs, sanPairs)
	}
	for i, rawPair := range rawPairs {
		if sanPairs[i] != rawPair {
			t.Errorf("insight set differs at position %d: raw = %q, sanitized = %q\nfull raw:       %v\nfull sanitized: %v",
				i, rawPair, sanPairs[i], rawPairs, sanPairs)
		}
	}
}

// sortedCheckLevelPairs reduces a replay's insights to a sorted "check|level"
// multiset, the same shape scripts/check-replay-fidelity.sh compares (status
// per check), just at the models.Insight layer instead of the rendered JSON
// layer. A map keyed by check name would silently collapse a check that emits
// MULTIPLE insights (Hardening, Logs — see BUG-069) down to whichever one was
// seen last, hiding a real divergence in insight count; a sorted slice keeps
// every insight and every duplicate. Message text is deliberately NOT
// compared: a message that quotes a now-redacted value is EXPECTED to change
// wording; only a verdict (level) change, or a change in which/how-many
// insights fired, is a bug.
func sortedCheckLevelPairs(insights []models.Insight) []string {
	pairs := make([]string, 0, len(insights))
	for _, ins := range insights {
		pairs = append(pairs, ins.Check+"|"+ins.Level)
	}
	sort.Strings(pairs)
	return pairs
}
