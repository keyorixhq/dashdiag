package collectors

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// erroringCachedSource makes every Cached() call fail, forcing the *ViaSource
// gap-fallback branch regardless of platform.
type erroringCachedSource struct {
	source.Source
}

func (erroringCachedSource) Cached(string, func() ([]byte, error)) ([]byte, error) {
	return nil, errors.New("cache miss, forced")
}

// TestCloudEnvironmentViaSource_ReplaysRecordedValue guards replay fidelity: a
// captured cloud environment (e.g. EnvAWSEBS) must replay unchanged regardless
// of the replaying machine's own cloud/bare-metal status, since it feeds the
// cloud-aware ApplyThresholds NVMe-timeout downgrade.
func TestCloudEnvironmentViaSource_ReplaysRecordedValue(t *testing.T) {
	rec := source.NewRecorder(source.Live{})
	captured := platform.EnvAWSEBS
	blob, err := json.Marshal(captured)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := rec.Cached("platform/cloud-env", func() ([]byte, error) { return blob, nil }); err != nil {
		t.Fatalf("seed record: %v", err)
	}

	prev := SetSource(source.NewReplay(rec.Bundle()))
	defer SetSource(prev)

	if got := CloudEnvironmentViaSource(); got != platform.EnvAWSEBS {
		t.Errorf("CloudEnvironmentViaSource() = %v, want %v — replay must reflect the captured cloud, not the replaying host", got, platform.EnvAWSEBS)
	}
}

// TestCloudEnvironmentViaSource_LiveComputesFresh exercises the live path
// (source.Live's Cached always invokes produce()): the inner compute closure
// itself — platform.DetectCloudEnvironment() — must run and return without
// panicking, distinct from both the recorded-replay and gap-fallback tests
// above, which never reach the closure at all.
func TestCloudEnvironmentViaSource_LiveComputesFresh(t *testing.T) {
	prev := SetSource(source.Live{})
	defer SetSource(prev)

	// No assertion on the specific value (host-dependent); this exists to
	// exercise the produce() closure body under a live source.
	_ = CloudEnvironmentViaSource()
}

// TestCloudEnvironmentViaSource_GapFallsBackToNone guards the fallback for
// older bundles with no recording: Cached() erroring must fall back to
// EnvUnknown ("none"), the prior hardcoded behavior — never propagate the
// error or silently pick a live value.
func TestCloudEnvironmentViaSource_GapFallsBackToNone(t *testing.T) {
	prev := SetSource(erroringCachedSource{})
	defer SetSource(prev)

	if got := CloudEnvironmentViaSource(); got != platform.EnvUnknown {
		t.Errorf("CloudEnvironmentViaSource() = %v, want EnvUnknown fallback on cache miss", got)
	}
}

// TestProfileViaSource_ReplaysRecordedValue guards replay fidelity: a captured
// Profile (distro/init-system/etc.) must replay unchanged, since it feeds
// buildHealthCollectors and distro-specific collector behavior — replaying a
// Debian capture on an Alpine box must NOT run Alpine's profile.
func TestProfileViaSource_ReplaysRecordedValue(t *testing.T) {
	rec := source.NewRecorder(source.Live{})
	captured := platform.Profile{OS: "linux", Distro: "debian", InitSystem: "systemd"}
	blob, err := json.Marshal(captured)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := rec.Cached("platform/profile", func() ([]byte, error) { return blob, nil }); err != nil {
		t.Fatalf("seed record: %v", err)
	}

	prev := SetSource(source.NewReplay(rec.Bundle()))
	defer SetSource(prev)

	got := ProfileViaSource()
	if got.Distro != "debian" || got.InitSystem != "systemd" {
		t.Errorf("ProfileViaSource() = %+v, want captured debian/systemd profile", got)
	}
}

// TestProfileViaSource_LiveComputesFresh exercises the live path (source.Live's
// Cached always invokes produce()): the inner compute closure — platform.Detect()
// — must run and return without panicking, distinct from the recorded-replay and
// gap-fallback tests above, which never reach the closure at all.
func TestProfileViaSource_LiveComputesFresh(t *testing.T) {
	prev := SetSource(source.Live{})
	defer SetSource(prev)

	got := ProfileViaSource()
	if got.OS == "" {
		t.Error("expected a non-empty OS field from a live ProfileViaSource() call")
	}
}

// TestProfileViaSource_GapFallsBackToLiveDetect guards the documented gap
// fallback: on a Cached() miss (older bundle with no recording), ProfileViaSource
// must fall back to a live platform.Detect() rather than returning a zero-value
// Profile or propagating the error — the prior behavior before this seam existed.
func TestProfileViaSource_GapFallsBackToLiveDetect(t *testing.T) {
	prev := SetSource(erroringCachedSource{})
	defer SetSource(prev)

	got := ProfileViaSource()
	want := platform.Detect()
	if got.OS != want.OS {
		t.Errorf("ProfileViaSource() fallback OS = %q, want live Detect() OS %q", got.OS, want.OS)
	}
}
