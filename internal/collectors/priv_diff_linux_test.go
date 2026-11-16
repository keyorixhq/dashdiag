//go:build linux

package collectors

// RTN1 — privilege differential through the fake source seam.
//
// The invariant this file guards is the "non-root false verdict" bug class
// (BUG-064/066/067/070, …) at the COLLECTOR level: a collector that reads a
// root-gated input (/etc/shadow, sshd_config 0600 on RHEL, /var/log/*, audit
// logs, /proc/<pid>/…) must, when that read is denied the way a real
// unprivileged run sees it (EACCES), degrade HONESTLY — it must set the typed
// "unreadable" flag that tells the analysis layer "this was not audited" and it
// must NOT populate any finding field from bytes it could not read. The denied
// (non-root) model must never look HEALTHIER than the readable (root) model.
//
// We build the SAME logical host state twice through the seam: once readable
// (root) and once with the privileged path denied (non-root). A denyingSource
// wraps a Bundle-backed Replay and returns a genuine os.IsPermission error for
// the configured root-gated paths/commands — exactly the shape live.go would
// hand back for a 0600 file an unprivileged process opened — so the real
// collector code runs unchanged against a faithful EACCES, not a test stub.
//
// The analysis-side half of the differential (the non-root VERDICT is identical
// or Unverified-needs_root, never floored healthier) is guarded in
// internal/analysis (needsroot_test.go, storage_nonroot_invariant_test.go) and
// cannot be exercised here without collectors importing analysis (forbidden
// import direction). This file pins the collector half: the honesty of the
// MODEL the verdict is computed from.

import (
	"context"
	"io/fs"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// denyingSource models a non-root run: every path in denyRead and every command
// whose key is in denyRun returns a present-but-unreadable (os.IsPermission)
// error, as if the process lacked the privilege to open a 0600 file or run a
// root-only tool. Everything else serves from the readable Bundle, so the root
// and non-root runs see the SAME logical host — only the privilege differs.
type denyingSource struct {
	*source.Replay
	denyRead map[string]bool
}

func (d *denyingSource) ReadFile(path string) ([]byte, error) {
	if d.denyRead[path] {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	}
	return d.Replay.ReadFile(path)
}

// privDiffCase is one collector's root-gated read reduced to a driveable unit:
// seed builds the readable host state into a Bundle; run invokes the real parse
// function against the active source and returns the populated model; denied is
// the set of paths the non-root run cannot read. healthy reports whether a model
// carries any concrete finding (something the verdict could act on); unreadable
// reports whether the model set its typed "not audited" disclosure flag.
type privDiffCase struct {
	name       string
	denied     []string
	seed       func(b *source.Bundle, content []byte)
	run        func() *models.SecurityInfo
	healthy    func(*models.SecurityInfo) bool // true => model asserts a concrete, actionable finding
	unreadable func(*models.SecurityInfo) bool // true => model disclosed "could not audit"
}

// shadowCase drives parsePasswordAging, which reads the root-only /etc/shadow.
func shadowCase() privDiffCase {
	var info *models.SecurityInfo
	return privDiffCase{
		name:   "shadow/parsePasswordAging",
		denied: []string{"/etc/shadow"},
		seed: func(b *source.Bundle, content []byte) {
			b.PutFile("/etc/shadow", content)
			// /etc/passwd is world-readable: present in BOTH runs.
			b.PutFile("/etc/passwd", []byte("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"))
		},
		run: func() *models.SecurityInfo {
			info = &models.SecurityInfo{}
			parsePasswordAging(info)
			return info
		},
		healthy: func(i *models.SecurityInfo) bool {
			// A concrete, actionable finding derived from /etc/shadow bytes.
			return len(i.EmptyPasswordAccounts) > 0 || len(i.StalePasswordAccounts) > 0
		},
		unreadable: func(i *models.SecurityInfo) bool { return i.ShadowUnreadable },
	}
}

// sshCase drives parseSSHConfig, which reads sshd_config (0600 on RHEL/Rocky:
// unreadable without root, and `sshd -T` prints "Permission denied" non-root).
func sshCase() privDiffCase {
	var info *models.SecurityInfo
	return privDiffCase{
		name:   "ssh/parseSSHConfig",
		denied: []string{"/etc/ssh/sshd_config"},
		seed: func(b *source.Bundle, content []byte) {
			// Isolate the file-read seam: sshd -T absent (so the file path is
			// taken), drop-in globs empty (no extra config), main file = content.
			b.PutCmdNotFound("sshd", []string{"-T"})
			b.PutGlob("/etc/ssh/sshd_config.d/*.conf", nil)
			b.PutGlob("/etc/ssh/sshd_config.d/*.cfg", nil)
			b.PutFile("/etc/ssh/sshd_config", content)
		},
		run: func() *models.SecurityInfo {
			info = &models.SecurityInfo{}
			parseSSHConfig(context.Background(), info)
			return info
		},
		healthy: func(i *models.SecurityInfo) bool {
			// parseSSHConfig always sets the directive booleans; the only
			// honest "I audited SSH" signal is a named audit source. A non-root
			// run that could not read any config must leave this empty.
			return i.SSHAuditSource != ""
		},
		unreadable: func(i *models.SecurityInfo) bool { return i.SSHConfigUnreadable },
	}
}

func privDiffCases() []privDiffCase { return []privDiffCase{shadowCase(), sshCase()} }

// runReadable builds the readable (root) model; runDenied builds the non-root
// model with the case's root-gated paths returning EACCES. Both run the real
// collector code against the same seeded host state.
func (c privDiffCase) runReadable(t testing.TB, content []byte) *models.SecurityInfo {
	t.Helper()
	b := source.NewBundle()
	c.seed(b, content)
	prev := SetSource(source.NewReplay(b))
	defer SetSource(prev)
	return c.run()
}

func (c privDiffCase) runDenied(t testing.TB, content []byte) *models.SecurityInfo {
	t.Helper()
	b := source.NewBundle()
	c.seed(b, content)
	deny := map[string]bool{}
	for _, p := range c.denied {
		deny[p] = true
	}
	prev := SetSource(&denyingSource{Replay: source.NewReplay(b), denyRead: deny})
	defer SetSource(prev)
	return c.run()
}

// assertPrivDifferential is the shared oracle. For any host state:
//   (1) the denied (non-root) model MUST disclose it could not audit (typed
//       unreadable flag) — this is what names, to the verdict layer, exactly
//       what was NOT checked;
//   (2) the denied model MUST NOT carry a concrete finding — a finding derived
//       from bytes it never read would be fabricated;
//   (3) the denied model is never HEALTHIER than the readable one: it may only
//       drop to "unverified", never report a clean/benign audit it didn't do.
func assertPrivDifferential(t testing.TB, c privDiffCase, readable, denied *models.SecurityInfo) {
	t.Helper()
	if !c.unreadable(denied) {
		t.Fatalf("%s: non-root (EACCES) model did NOT set its unreadable disclosure flag — "+
			"analysis would treat the un-audited source as 'nothing wrong' (false-OK, BUG-064/066 class)", c.name)
	}
	if c.healthy(denied) {
		t.Fatalf("%s: non-root (EACCES) model carries a concrete finding derived from a source it could not read — "+
			"a fabricated verdict from unreadable data", c.name)
	}
	// Direction check: whatever the root run could see, the non-root run must
	// not claim MORE verified health. Here "more health" = asserting an audit
	// source / finding set that the readable run earned by actually reading.
	if c.healthy(denied) && !c.healthy(readable) {
		t.Fatalf("%s: non-root model is healthier than root — it claims a finding root did not", c.name)
	}
}

// TestPrivDifferential_SeamSmoke is the green half of the red/green proof: with
// the real collector code, every case's denied model degrades honestly on a
// representative readable host state.
func TestPrivDifferential_SeamSmoke(t *testing.T) {
	seeds := map[string][]byte{
		"shadow/parsePasswordAging": []byte("root:$6$abc$def:19000:0:99999:7:::\nalice::19000:0:99999:7:::\nbob:$6$x$y:19000:0:0:7:::\n"),
		"ssh/parseSSHConfig":        []byte("PermitRootLogin yes\nPasswordAuthentication no\nX11Forwarding yes\n"),
	}
	for _, c := range privDiffCases() {
		t.Run(c.name, func(t *testing.T) {
			content := seeds[c.name]
			readable := c.runReadable(t, content)
			// Sanity: the readable run actually produced the finding we planted,
			// so the denied-side assertions are meaningful (not vacuously true).
			if !c.healthy(readable) {
				t.Fatalf("%s: readable model produced no finding from the seed — fixture premise wrong", c.name)
			}
			if c.unreadable(readable) {
				t.Fatalf("%s: readable model wrongly set its unreadable flag on a readable source", c.name)
			}
			denied := c.runDenied(t, content)
			assertPrivDifferential(t, c, readable, denied)
		})
	}
}

// FuzzPrivDiffSeam drives the differential with fuzzer-controlled host state.
// The first byte selects which root-gated collector; the rest is the readable
// content (an /etc/shadow or sshd_config body). For every input the denied
// (non-root) model must degrade honestly (assertPrivDifferential).
//
// Resource meters (per Andrei's DL1 requirement): we bound bytes allocated and
// wall time of the collector parse via resource.Check. ONLY memory + time are
// metered: the seam serves from an in-memory Bundle, so the parse opens no file
// descriptors (no fd oracle needed) and spawns no goroutines (GoroutineDiff is
// reported but not asserted) — the same stance resource.go documents for the
// in-process DL1 targets. Factor 128x + 1 MiB floor is calibrated from the
// baseline run (parsePasswordAging allocates a per-line SplitN slice plus the
// human-accounts map; the readable path dominates, the denied path returns at
// the first EACCES). No disk/network/sleep meter: a replayed Bundle touches
// neither, which is itself part of the read-only claim this seam makes.
func FuzzPrivDiffSeam(f *testing.F) {
	f.Add(byte(0), []byte("root:$6$a$b:19000:0:99999:7:::\nalice::19000:0:99999:7:::\n"))
	f.Add(byte(1), []byte("PermitRootLogin yes\nPasswordAuthentication no\n"))
	f.Add(byte(0), []byte(""))
	f.Add(byte(1), []byte("Match Address 10.0.0.0/8\nPasswordAuthentication yes\n"))
	f.Add(byte(0), []byte("::::::::\n:::\n\n\n"))
	f.Add(byte(1), []byte("#comment only\n   \nKexAlgorithms curve25519-sha256\n"))

	cases := privDiffCases()
	f.Fuzz(func(t *testing.T, sel byte, content []byte) {
		c := cases[int(sel)%len(cases)]

		var readable, denied *models.SecurityInfo
		resource.Check(t, len(content), 128, func() {
			readable = c.runReadable(t, content)
			denied = c.runDenied(t, content)
		})

		// The differential invariant must hold for ANY host state, regardless of
		// whether the readable run found anything. If the readable run itself
		// flagged the source unreadable (it never should, but the fuzzer may feed
		// a path-breaking body), there is no differential to check.
		if c.unreadable(readable) {
			t.Fatalf("%s: readable model set its unreadable flag on a readable source (content=%q)", c.name, content)
		}
		if !c.unreadable(denied) {
			t.Fatalf("%s: non-root model failed to disclose unreadable source (content=%q)", c.name, content)
		}
		if c.healthy(denied) {
			t.Fatalf("%s: non-root model fabricated a finding from unreadable data (content=%q)", c.name, content)
		}
	})
}
