package selfupdate

import (
	"net/http"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// Resource-oracle calibration (PD1). validateAssetURL drives net/url.Parse and a
// host-allowlist check. Measured allocation is a flat ~144 B regardless of input
// size (0–5x amplification; it rejects/early-returns before building anything
// large), so the 1 MiB AllocFloor is the active bound. factor 64 is conservative
// and still trips any super-linear parse blow-up. No goroutines (measured Δ=0),
// no disk I/O — disk/fd oracle N/A.
const (
	pd1AssetURLAllocFactor = 64
	pd1MaxGoroutineDiff    = 16
)

// FuzzValidateAssetURLFailClosed fuzzes validateAssetURL — the gate every
// self-update download URL passes before dsd (running as root during `dsd
// update`) fetches a release asset. The URL comes from the GitHub release JSON,
// i.e. a remote, attacker-influenceable source. validateAssetURL feeds it to
// net/url.Parse and then decides, from u.Hostname(), whether to dial it.
//
// Oracle (fail-closed + validation/dial consistency, not crash-only): whenever
// validateAssetURL accepts a URL, the host that net/http will ACTUALLY dial for
// that same URL string must be one of the allowlisted hosts, and (when the
// scheme check is active) the scheme must be https. This catches the dangerous
// class where the validator's notion of "host" disagrees with the HTTP client's
// — a URL that looks like github.com to the allowlist check but resolves to an
// attacker host at dial time (SSRF / asset-swap to a root-executed binary).
//
// INVARIANT (see INVARIANTS.d note): validateAssetURL never accepts a URL whose
// http.Request dial host falls outside assetURLAllowedHosts.
//
// Note on test configuration: the package TestMain widens the allowlist with
// 127.0.0.1 and relaxes requireHTTPSAssetURL so the existing httptest-based
// download tests work. This oracle reads those same live vars, so it asserts
// consistency, not the production allowlist CONTENTS. What it therefore does NOT
// verify: that the shipped allowlist is itself correct/minimal, nor the
// signature/checksum verification that follows a successful download.

func FuzzValidateAssetURLFailClosed(f *testing.F) {
	f.Add("https://github.com/keyorixhq/dashdiag/releases/download/v1/dsd-linux-amd64")
	f.Add("https://objects.githubusercontent.com/x")
	f.Add("https://github.com@evil.example/x")   // userinfo spoof
	f.Add("https://github.com\t.evil.example/x") // tab/control injection
	f.Add("http://github.com/x")                 // non-https
	f.Add("https://127.0.0.1:8080/x")            // loopback (test-widened)
	f.Add("https://evil.example/x")
	f.Add("://nonsense")
	f.Add("")

	f.Fuzz(func(t *testing.T, rawURL string) {
		// Resource oracle: bound validateAssetURL's allocation/time and record
		// goroutine growth. The validation/dial-host consistency assertions below
		// are unchanged.
		var verr error
		rr := resource.Check(t, len(rawURL), pd1AssetURLAllocFactor, func() {
			verr = validateAssetURL(rawURL)
		})
		if rr.GoroutineDiff > pd1MaxGoroutineDiff {
			t.Fatalf("goroutine growth: validateAssetURL left %d extra goroutines (input=%d B)", rr.GoroutineDiff, len(rawURL))
		}
		if verr != nil {
			return // rejection is the correct, safe outcome
		}
		// Accepted: the URL must be something net/http can build a request for,
		// and the host it would dial must be allowlisted.
		req, rerr := http.NewRequest(http.MethodGet, rawURL, nil)
		if rerr != nil {
			t.Fatalf("validateAssetURL accepted %q but http.NewRequest rejects it: %v", rawURL, rerr)
		}
		host := req.URL.Hostname()
		if !assetURLAllowedHosts[host] {
			t.Fatalf("validateAssetURL accepted %q whose HTTP dial host %q is NOT allowlisted — validation/dial host mismatch (SSRF/asset-swap)", rawURL, host)
		}
		if requireHTTPSAssetURL && req.URL.Scheme != "https" {
			t.Fatalf("validateAssetURL accepted non-https URL %q (scheme %q)", rawURL, req.URL.Scheme)
		}
	})
}
