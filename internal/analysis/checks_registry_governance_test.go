package analysis

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestAllChecksRegistered is a repo-wide completeness tripwire, same idiom as
// internal/models/falseok_signal_registry_test.go and internal/collectors/
// parallel_mutation_governance_test.go: it does not test behaviour, it tests
// that a class of bug cannot silently reappear.
//
// The problem TestChecksNeverSilentlySkip (checks_never_silent_test.go) alone
// does not solve: its neverSilentChecks table only proves what someone
// remembered to list. internal/analysis has 174 check<X> functions; a new one
// added tomorrow with a silent give-up path is outside that table by default —
// the exact failure mode the table exists to prevent, one level up.
//
// This test finds every check function CAPABLE of that bug class — one that
// actually READS a field on its own input parameter whose name signals "this
// could not be measured/verified" — and requires it to be provably safe:
// either exercised by a neverSilentChecks row (checkFn matches by name), or
// in checkExemptions with a stated reason. A capable-but-unlisted function
// fails the build.
//
// Candidacy is deliberately at FIELD-READ granularity, not "does the
// function's parameter TYPE have such a field anywhere": models.SecurityInfo
// alone has 9 matching fields (NeedsRoot, ShadowUnreadable, SudoersUnreadable,
// ...) and is the first parameter of ~15 different check<X> functions, most
// of which never touch any of those 9 fields — type-level candidacy flagged
// all 15 as false positives. Scanning each function's own body for a
// selector expression on its own parameter (`sec.NeedsRoot`, not just
// "takes a SecurityInfo") is what makes the signal precise.
//
// Functions that reference no such field (the majority — internal/analysis
// has 174 check<X> functions total, 81 are field-read candidates as of
// writing, all covered by a table row or a checkExemptions entry below) need
// no registry entry at all: the classification IS the AST scan itself,
// re-run fresh on every test execution against the CURRENT body of every
// check function, not a hand-maintained list of ~90 names that could go
// stale. This mirrors falseok_signal_registry_test.go exactly: that test
// also only requires a registry entry for fields matching its regex, not one
// for every field in internal/models. If a check function is later edited to
// start reading an existing-but-previously-ignored unverified-signal field,
// it becomes a candidate on the very next run, automatically — no one has to
// remember to add it here.
//
// Scope: only the first parameter of each check function is inspected, and
// only when its type is models.X, *models.X, or []models.X — the convention
// every check function but one follows. checkSecurityDrift(*baseline.SecurityDiff)
// is the sole exception; baseline.SecurityDiff is out of this test's scope
// (same scope boundary falseok_signal_registry_test.go draws around
// internal/models — it does not reach into internal/baseline either).
func TestAllChecksRegistered(t *testing.T) {
	analysisDir := packageDirForGovernanceTest(t, "internal/analysis")
	modelsDir := packageDirForGovernanceTest(t, "internal/models")

	fset := token.NewFileSet()
	allFuncs := parseAllFuncDecls(t, fset, analysisDir)
	if len(allFuncs) < 150 { // sanity: repo has 900+ funcs in internal/analysis as of writing
		t.Fatalf("only found %d funcs under %s — the walk is broken, "+
			"this test would silently police nothing", len(allFuncs), analysisDir)
	}
	checkFns := checkFunctionInfos(allFuncs)
	if len(checkFns) < 150 { // sanity: repo has 174 check<X> functions as of writing
		t.Fatalf("only found %d check<X> functions under %s — the walk is broken, "+
			"this test would silently police nothing", len(checkFns), analysisDir)
	}

	modelFields := parseModelStructFields(t, fset, modelsDir)
	if len(modelFields) < 100 { // sanity: internal/models has 100+ structs as of writing
		t.Fatalf("only found %d model structs under %s — the walk is broken, "+
			"this test would silently police nothing", len(modelFields), modelsDir)
	}

	covered := map[string]bool{}
	for _, c := range neverSilentChecks {
		covered[c.checkFn] = true
	}

	var candidates, violations []string
	for fnName, fn := range checkFns {
		var candidateFields []string
		for _, f := range modelFields[fn.paramType] {
			if unverifiedSignalPattern.MatchString(f) {
				candidateFields = append(candidateFields, f)
			}
		}
		if len(candidateFields) == 0 {
			continue
		}
		referenced := referencedFields(fn.body, fn.paramVar, candidateFields, allFuncs, map[string]bool{})
		if len(referenced) == 0 {
			continue
		}
		candidates = append(candidates, fmt.Sprintf("%s (%s.%s)", fnName, fn.paramType, strings.Join(referenced, "/")))
		if covered[fnName] {
			continue
		}
		if _, exempted := checkExemptions[fnName]; exempted {
			continue
		}
		violations = append(violations, fmt.Sprintf("%s (models.%s.%s)", fnName, fn.paramType, strings.Join(referenced, "/")))
	}
	sort.Strings(candidates)
	sort.Strings(violations)
	t.Logf("%d of %d check functions read an unverified-signal field on their own input: %s",
		len(candidates), len(checkFns), strings.Join(candidates, ", "))

	if len(violations) > 0 {
		t.Errorf("%d check function(s) read a field signalling an unmeasured state but are neither "+
			"proven safe (a neverSilentChecks row in checks_never_silent_test.go) nor exempted with a "+
			"reason (checkExemptions in this file):\n  %s\n\n"+
			"Either add a neverSilentChecks row reproducing the unmeasured state and asserting an "+
			"INFO insight names it, or — only if the silence is genuinely correct — add a "+
			"checkExemptions entry explaining why. (Completeness tripwire — see this file's doc "+
			"comment.)", len(violations), strings.Join(violations, "\n  "))
	}

	// Stale-entry detection: a neverSilentChecks.checkFn or checkExemptions key
	// that no longer names a real check<X> function is dead weight that would
	// mask the row/entry silently doing nothing.
	var staleCovered, staleExempt []string
	for fn := range covered {
		if _, ok := checkFns[fn]; !ok {
			staleCovered = append(staleCovered, fn)
		}
	}
	for fn := range checkExemptions {
		if _, ok := checkFns[fn]; !ok {
			staleExempt = append(staleExempt, fn)
		}
	}
	sort.Strings(staleCovered)
	sort.Strings(staleExempt)
	if len(staleCovered) > 0 {
		t.Errorf("neverSilentChecks references function(s) that no longer exist: %s",
			strings.Join(staleCovered, ", "))
	}
	if len(staleExempt) > 0 {
		t.Errorf("checkExemptions references function(s) that no longer exist: %s",
			strings.Join(staleExempt, ", "))
	}
}

// unverifiedSignalPattern matches a struct field name that signals "this
// could not be measured/verified" — the input to the false-clean bug class.
// Broader than internal/models' own unverifiedSignalRe (falseok_signal_registry_test.go)
// by one suffix: Available. That guard deliberately excludes Available because
// its canonical contract (runner.IsAvailable / models/availability.go) is
// "not applicable on this platform/host", a different, legitimate silence.
// This test's audit found that contract gets misused at least once
// (checkCloudMeta: the collector only runs after IsCloudInstance() already
// confirmed a live probe succeeded, so Available==false there means "checked,
// failed" — not "not applicable") — so Available is included here as a
// candidate signal too. Every hit still requires a human classification
// (table row or checkExemptions reason); this regex only decides who has to
// make that call, never the answer.
var unverifiedSignalPattern = regexp.MustCompile(`(Verified|Unverified|Unreadable|Queried|Reachable|ScanFailed|ReadFailed|NeedsRoot|NeedRoot|ScanOK|Checked|Measured|Available)$`)

// checkExemptions lists check<X> function names explicitly allowed to return
// silently on an unverified-signal field they read, each with the reason
// it's safe. Reason required — this is not a suppression list, it's what
// makes the exemption reviewable (same framing as
// parallel_mutation_governance_test.go's parallelMutationExemptions).
var checkExemptions = map[string]string{
	"checkEntropy": "Deliberate, not a gap: Available=false only ever comes from the non-Linux stub " +
		"(entropy_notlinux.go) — genuinely not applicable off-Linux. A real Linux read failure never " +
		"reaches this function: EntropyCollector.Collect() returns a Go error in that case, surfaced as " +
		"checks[].status==\"ERROR\", not Available=false. See the inline comment on checkEntropy.",
	"checkPressure": "Deliberate, not a gap: PSI absence is overwhelmingly a legitimate \"not applicable " +
		"on this kernel\" state (pre-4.20, or PSI disabled at build/boot) — disclosing it would add INFO " +
		"noise on every older-kernel run for a failure mode that essentially does not occur. See the " +
		"inline comment on checkPressure.",
	"checkDNS": "Available=false is the non-Linux stub only — every field is the zero value and Linux " +
		"always sets Available:true, so this never suppresses a real broken host. See the inline comment " +
		"on checkDNS.",
	"checkSnapper": "snapper not installed — not an error, just skip. See the inline comment on checkSnapper.",
	"checkKdump": "Not installed, or admin deliberately left it off — not a fault. See the inline comment " +
		"on checkKdump.",
	"checkSystemd": "Not present on this platform — hide the row entirely. See the inline comment on " +
		"checkSystemd.",
	"checkIPMI": "The preceding Status==\"error\" branch already catches the real sensor-read-failure " +
		"case, making the plain !Available fall-through safe. See the inline comment on checkIPMI.",
	"checkPackageDBHealth": "Defensive: the collector never sets DBUpdatesBlocked without " +
		"DBHealthChecked also being true (verified 2026-07-08), gated on both anyway. See the inline " +
		"comment on checkPackageDBHealth.",
	"checkDocker": "StatusReason==\"\" on the !Available path is deliberate, not a gap: the collector " +
		"(collectors/docker.go) reserves StatusReason for an installed-but-unusable runtime — Podman is " +
		"daemonless, so \"no socket\" is its normal idle state, not a fault. A host with nothing usable " +
		"at all leaves StatusReason empty on purpose. See the inline comment on checkDocker.",
	"checkFstab": "Checked==false conflates \"no /etc/fstab\" with \"uuid/partuuid symlink dirs " +
		"unreadable\" — the distinction does not exist at the collector, so it cannot be recovered here. " +
		"Fixing requires a collector-layer signal (a CheckedReason field distinguishing the two states); " +
		"see /tmp/fstab-collector-gap.md for the fix shape. Not implemented — collector-layer work, out " +
		"of scope for this guard.",

	// --- Audited 2026-08-11 during the TestAllChecksRegistered build-out: every ---
	// entry below the SAFE/KNOWN-BUG/UNCLEAR headers was produced by a systematic
	// pass over all 62 candidates this test's mechanical scan found beyond the
	// original 8-entry table (cross-referenced against internal/models/
	// falseok_signal_registry_test.go's 2026-07-08 audit notes, then re-verified
	// against current code — that prior audit's "safe" verdict was NOT trusted
	// blindly, since this same pass is what found the checkCloudMeta/checkAWS/
	// checkAzure/checkGCP/checkServiceRestart bugs that got fixed instead of
	// exempted). Four checks turned out to be live bugs and were fixed (see the
	// neverSilentChecks rows above); four more are confirmed live bugs NOT YET
	// fixed (real, larger-scope work — restructuring or a model field addition,
	// deferred rather than rushed); six are genuinely ambiguous from static
	// reading alone. Grep this file for "KNOWN BUG" / "UNCLEAR" to find the two
	// groups that are not actually resolved.

	// --- SAFE (48): the unmeasured-signal path is a genuine not-applicable gate, ---
	// or is already disclosed correctly by the function or a sibling in the same
	// dispatcher.
	"checkAuditd": "Available is a genuine \"auditctl not installed\" existence gate (no query can " +
		"fail there); AuditLogSizeUnreadable is checked before the size threshold, so an unreadable log " +
		"can't fall through to a clean 0-size read.",
	"checkBIND": "PortsChecked discloses via an explicit INFO when `ss` is unavailable.",
	"checkBtrfsVolume": "DevReadUnverified discloses via INFO; the CRIT that runs first only fires on a " +
		"genuinely-missing device placeholder, never a false one.",
	"checkCVEHealth": "ScanFailed is consulted first in cveScanUnavailable, ahead of every fallback path " +
		"including the apt/tdnf switch arms.",
	"checkCeph": "Available=false correctly splits into NeedsRoot (INFO), configured-but-unreachable " +
		"(CRIT), and genuine non-member client (nil) rather than blanket silence.",
	"checkCgroupV2": "Available is set unconditionally true whenever this function is reached; the " +
		"collector itself returns nil on the genuine not-applicable state (no cgroupfs) before Collect " +
		"ever builds a CgroupV2Info.",
	"checkCloudInit": "Available is unconditionally true whenever Collect() runs (Linux), and the " +
		"collector is only invoked behind a local presence gate (CLI on PATH or status.json exists) — no " +
		"live-probe failure can reach !Available. StatusUnverified is explicitly disclosed via INFO.",
	"checkContainerd": "Every unmeasured state (socket absent, permission-denied) is disclosed (WARN or " +
		"INFO); the heuristic only runs behind a gate requiring one of those two states to be true.",
	"checkCron": "!FailureScanOK discloses via an explicit INFO; the earlier return is the genuine " +
		"no-cron-daemon case.",
	"checkDisk": "Holds no unverified-signal logic of its own; unconditionally delegates to " +
		"checkDiskExtras, which discloses.",
	"checkDiskExtras": "ZFSListReadFailed discloses via INFO; the ZFSPools no-op is sound because both " +
		"collectors share the same zpool-binary presence gate.",
	"checkDockerResources": "The Available check is redundant dead code (the parent checkDocker already " +
		"gated on it and disclosed); IPForwardChecked false is a genuine \"no /proc on macOS/proc-less " +
		"container\" not-applicable state.",
	"checkGPUDevice": "Unreadable=true returns an explicit CRIT before any per-metric scoring.",
	"checkHA": "Available=false is a genuine \"no HA stack installed\" gate; the real privilege gap " +
		"(StatusReadable) is separately disclosed via INFO.",
	"checkHWRaid": "Available=false is only reachable as \"no controller data at all\" (registration-" +
		"gated); NeedsRoot/ReadFailed are always co-set with Available=true in every collector write path.",
	"checkISCSI": "NeedsRoot is tested first (INFO); Available=false is defensively unreachable in " +
		"practice — the collector sets it true immediately whenever iscsiadm exists.",
	"checkJournalActivity": "ErrorCountUnverified is only ever set alongside ErrorCount==0, so the " +
		"disclosure branch is always reached when the count is unverified.",
	"checkJournalHealthInsights": "Pure fan-out to other checkJournal* functions — adds no branch of " +
		"its own.",
	"checkK8sNodeDaemons": "KubeletChecked/ContainerdChecked are genuine node-marker gates (not " +
		"privilege-related); FirewalldChecked correctly requires firewalld to be active first.",
	"checkK8sServicesChain": "KubeServicesChecked=false for mode nft/\"\" is a genuine no-verdict state " +
		"in isolation — the disclosure gap under root belongs to checkK8sOSLayerCoverageGaps (see KNOWN " +
		"BUG below), not this function.",
	"checkKVM": "!Detected is correctly silent (no libvirt installed); the dangerous \"enumeration " +
		"failed\" case is caught separately as a WARN.",
	"checkKVMVMs": "VMsUnreadable unconditionally discloses via WARN.",
	"checkKernelRetention": "Available requires both a nonzero installed-kernel count and an identified " +
		"package manager; both are genuine \"can't identify\" gates with no green line at risk.",
	"checkLVM": "Holds no unverified-signal logic of its own; unconditionally delegates all four " +
		"*ReadFailed disclosures to checkLVMRaid.",
	"checkLVMRaid": "PVReadFailed/VGReadFailed/LVReadFailed are unconditionally disclosed; RaidReadFailed " +
		"is gated on VGs existing, but VGReadFailed already fires in that same run so nothing goes " +
		"silently clean.",
	"checkLivePatch": "Available=false is \"nothing loaded, nothing to verify\"; the genuinely-unmeasured " +
		"case has its own UnverifiedPatches list and explicit INFO.",
	"checkLogs": "NeedsRoot discloses via INFO before any other verdict; ErrorCountUnverified is " +
		"delegated to checkJournalActivity, which discloses (see above).",
	"checkMTE": "Available is set unconditionally true by the collector, which is only registered behind " +
		"IsMTEAvailable() (arm64 + CPU/kernel \"mte\" feature flag) — a real host never reaches this " +
		"function with Available=false. See the inline comment on checkMTE.",
	"checkMongoDB": "ConnAvailable is an unrelated int field (a regex false-positive on the field name, " +
		"not a bool unverified-signal); the real \"probe failed\" state (MetricsRead=false) is explicitly " +
		"disclosed elsewhere in this function.",
	"checkMultipath": "Available is a strict, privilege-independent not-installed gate; the real " +
		"probe-failed case is a separate Status==\"error\" WARN.",
	"checkNUMA": "Available=false means <=1 NUMA node — a genuine not-applicable state, using the same " +
		"predicate the collector uses to decide whether to register at all.",
	"checkPVE": "The dispatcher gates on IsPVE/NeedsRoot/APIReachable before delegating to any sub-check; " +
		"APIReachable and NeedsRoot are both disclosed with their own WARN/INFO before any sub-check runs.",
	"checkPVEBackups": "BackupVerified is explicitly disclosed via INFO (\"backup health NOT verified\") " +
		"when the vzdump query failed and no on-disk fallback found anything.",
	"checkPVECluster": "HAVerified is explicitly disclosed via INFO when the HA endpoint answered but was " +
		"unparseable (only reached past the HAFencingOK CRIT, a genuinely different fault).",
	"checkPVEStorage": "StoragesVerified is explicitly disclosed via INFO before iterating storages.",
	"checkPVETaskErrors": "TasksVerified is explicitly disclosed via INFO when the task list itself " +
		"couldn't be read.",
	"checkSUSEConnect": "StatusUnverified is set only on the RHEL parse-failure path and is consumed " +
		"only by checkRHELSubscription (in the table above), which discloses it before the default " +
		"\"current\" case can fire.",
	"checkSUSESecurityHardening": "SupportconfigAvailable=false is a pure existence check on " +
		"world-readable paths (no query exists to fail there); it only suppresses two INFO-level hygiene " +
		"notices, no green line at risk.",
	"checkSecurity": "A pure dispatcher with no early return of its own; unconditionally absorbs " +
		"checkSecurityAuditGaps' and checkSUSESecurityHardening's disclosures.",
	"checkSecurityAuditGaps": "All five fields (NeedsRoot, SSHConfigUnreadable, ShadowUnreadable, " +
		"FailedLoginsUnreadable, PAMFailuresUnreadable) branch to an explicit INFO, verified against the " +
		"current collector setters.",
	"checkSteamOS": "A pure dispatcher; both sub-checks (checkSteamOSNetwork, checkSteamOSUpdate) run " +
		"unconditionally on a Detected host and disclose on their own.",
	"checkSteamOSNetwork": "!UpdateServerReachable fails toward WARN, never silence.",
	"checkSteamOSUpdate": "!RAUCAvailable emits an explicit INFO naming the unverified state.",
	"checkTuned": "Available=false only when neither tuned-adm nor tuned.service exists — a genuine " +
		"not-installed gate.",
	"checkVMware": "Both StatAvailable and SCSIDisksChecked are disclosed or correctly gated; the " +
		"all-clean line can never fire over an unmeasured stat interface.",
	"checkVault": "Available is a genuine install-gate distinct from Reachable (no live probe runs " +
		"before it's set); Reachable and StatusRead are both properly disclosed.",
	"checkZFS": "ListReadFailed emits an INFO before iterating pools.",
	"checkZFSPool": "StatusReadFailed emits an INFO and returns early, correctly suppressing the " +
		"scrub-age check that would otherwise misread an unset value.",

	// --- KNOWN BUG, NOT YET FIXED (4): confirmed live silent-skip bugs, deferred ---
	// as larger-scope work (restructuring or a model field addition) rather than a
	// same-shape INFO-disclosure patch. Each needs its own follow-up.
	"checkDRBD": "KNOWN BUG, not fixed: the Unverified early-return (heuristics_storage.go) discards " +
		"already-parsed Resources. DRBDInfo.Unverified has two producers — v9/netlink non-root (Resources " +
		"empty, early-return loses nothing) and parseDRBDProc's partial /proc/drbd read (Unverified set " +
		"AFTER resources were already appended). On an 8.x host where /proc/drbd errors mid-read after a " +
		"resource was parsed as cs:SplitBrain, the CRIT is dropped and exit code flips 2->0. Fix: check " +
		"Unverified only as a fallback when Resources is empty, not unconditionally first.",
	"checkK8s": "KNOWN BUG, not fixed: the !APIReachable early-return (heuristics_virt.go) also skips " +
		"CheckK8sOSLayer, which does not depend on API reachability (systemd/sysfs/iptables facts). On a " +
		"k3s node with the service down, `dsd health --deep` reports nothing while `dsd k8s --deep` " +
		"(cmd/k8s.go's k8sOSLayerInsights, called independently) reports real kubelet/cert/CNI CRITs for " +
		"the identical host — the cmd<->health tally-drift class (#275) this architecture exists to " +
		"prevent. Fix: run CheckK8sOSLayer independently of the APIReachable gate.",
	"checkK8sOSLayerCoverageGaps": "KNOWN BUG, not fixed: OSLayerNeedsRoot (heuristics_virt.go) is a bare " +
		"uid==0 proxy, not a real per-check signal. KubeForwardChecked/KubeServicesChecked/CNIChecked go " +
		"false whenever the relevant tool is missing (not only under non-root — k3s's bundled iptables is " +
		"off-PATH and nft is frequently absent on a k3s node, per the code's own comment at k8s.go:742-" +
		"744), but disclosure only fires via OSLayerNeedsRoot. A ROOT run on such a node gets zero " +
		"disclosure and \"No OS-layer issues\". Fix: disclose on tool-missing directly, not just on " +
		"non-root, mirroring the already-fixed FlannelCNIUnreadable case.",
	"checkTransactional": "KNOWN BUG, not fixed: TransactionalInfo has no Unverified/NeedsRoot field at " +
		"all (models/maintenance.go), so a non-root or failed btrfs `subvolume get-default` read on " +
		"openSUSE MicroOS/SLE Micro (needs CAP_SYS_ADMIN) leaves RebootPending=false with Available=true " +
		"— a green \"Transactional: OK\" on a host with a staged, un-booted update. Same shape as the " +
		"checkFstab gap: needs a collector/model field addition before checkTransactional can disclose " +
		"it, out of scope for a same-shape INFO patch.",

	// --- UNCLEAR (6): real ambiguity found reading the code; a live-host repro or ---
	// a design-intent call is needed before deciding fix vs. exempt. Deferred rather
	// than forced into a bucket.
	"checkRancher": "UNCLEAR: Available conflates \"cattle-system namespace absent\" (safe) with " +
		"\"kubectl get namespace call failed\" (RBAC-restricted, a real gap) — mostly covered indirectly " +
		"by checkK8s's own APIReachable disclosure, but a reachable-API-with-restrictive-RBAC sliver " +
		"stays silent. Low severity: nothing renders a green \"Rancher OK\" line either way.",
	"checkKernelPatch": "UNCLEAR: CheckUnverified is disclosed correctly for the documented SUSE " +
		"zypp-lock case, but the Available=false fall-through (collectors/maintenance_linux.go:209-212) " +
		"also silently swallows a failed rpm probe (corrupt/locked rpmdb on RHEL/Oracle) — the row just " +
		"disappears from --json rather than a green OK, so lower severity than a false-OK but the same " +
		"root-cause conflation as the checkCloudMeta bug that WAS fixed.",
	"checkKsplice": "UNCLEAR: CheckUnverified is disclosed, but the collector's trigger " +
		"(err != nil && out == \"\") only catches errors that leave stdout empty — if a real " +
		"uptrack-upgrade failure (expired key, unreachable server) still writes to stdout, " +
		"countKsplicePending finds no matches and the row silently renders OK. Depends on whether uptrack " +
		"writes its error text to stdout or stderr — not verified from code alone.",
	"checkPackages": "UNCLEAR: the documented collector invariant (DBUpdatesBlocked never true without " +
		"DBHealthChecked also true) still holds, but DBHealthChecked=false has no disclosure anywhere. " +
		"Worse — flagged for follow-up, not this guard — packages_linux.go:200-201 returns checked=true, " +
		"blocked=false when the very first probe command fails under an already-expired context, " +
		"asserting a clean DB from a probe that never ran. That collector-layer bug is more severe than " +
		"this check function's own gap and needs its own fix.",
	"checkFirmware": "UNCLEAR: Available=false conflates \"fwupd not installed\" with \"fwupd present but " +
		"the version/status probe failed\" (D-Bus down, context timeout) — firmware.go sets both the same " +
		"way, and checkFirmware returns before its own \"could not be verified\" branch could fire. Not a " +
		"green OK (the row is dropped, not claimed clean), so lower severity; the real-world frequency of " +
		"the failure mode is unverified from code alone.",
	"checkNspawn": "UNCLEAR: Available=false conflates three states in the collector (nspawn_linux.go) — " +
		"machinectl absent (genuine N/A), `machinectl list` returning an error (systemd-machined down? a " +
		"real gap), and a successful-but-empty listing (genuine \"no containers running\", also benign). " +
		"Nspawn containers are a niche feature and the error-vs-empty split is unverified from code alone " +
		"— not a green OK either way (the row is dropped), so low priority.",
}

// checkFuncInfo is what checkFunctionInfos extracts per check<X> function:
// enough to test whether the function's body — or a same-package helper it
// delegates to (see referencedFields) — reads a candidate field on its own
// first parameter.
type checkFuncInfo struct {
	paramType string // bare models.X type name, e.g. "SecurityInfo"
	paramVar  string // the function's first parameter's identifier name, e.g. "sec"
	body      *ast.BlockStmt
}

// parseAllFuncDecls returns every top-level function declaration (not just
// check<X> ones — see referencedFields) in dir's non-test .go files, keyed by
// name. Panics on a duplicate (name collision across files in one package,
// which Go itself would refuse to compile — should never happen).
func parseAllFuncDecls(t *testing.T, fset *token.FileSet, dir string) map[string]*ast.FuncDecl {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	out := map[string]*ast.FuncDecl{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			out[fn.Name.Name] = fn
		}
	}
	return out
}

// checkFunctionInfos filters allFuncs down to check<X> functions whose first
// parameter is models.X (or *models.X) — the convention every check function
// but one follows (see this file's scope note) — and extracts their
// checkFuncInfo.
func checkFunctionInfos(allFuncs map[string]*ast.FuncDecl) map[string]checkFuncInfo {
	out := map[string]checkFuncInfo{}
	for name, fn := range allFuncs {
		if !isCheckFuncName(name) || fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
			continue
		}
		first := fn.Type.Params.List[0]
		typeName, ok := modelsTypeName(first.Type)
		if !ok || len(first.Names) == 0 {
			continue
		}
		out[name] = checkFuncInfo{
			paramType: typeName,
			paramVar:  first.Names[0].Name,
			body:      fn.Body,
		}
	}
	return out
}

// referencedFields returns the subset of candidateFields that body actually
// reads on the value bound to varName — either directly (`sec.NeedsRoot`
// when varName=="sec") or transitively, one call deep at a time, through a
// same-package helper the value is passed to unchanged.
//
// This codebase's check<X> functions routinely decompose into unexported
// per-aspect helpers (checkOCI delegates to ociIMDSInsights/ociAgentInsights/
// ociTimeSyncInsights/ociVNICInsights; checkAWS to awsENAInsights/
// awsEBSInsights/... — same shape) — the field read that actually gates
// silence often lives in the helper, not the check function itself. Scanning
// only the check function's own body missed checkOCI and checkAWS entirely
// (verified: they read IMDSChecked/EBSNeedsRoot/etc. only inside these
// helpers) despite both being real, already-covered candidates.
//
// allFuncs resolves a plain-identifier call (`ociIMDSInsights(o)`) to its
// FuncDecl; visited guards against runaway recursion on a call cycle (start
// each top-level call with an empty map).
func referencedFields(body *ast.BlockStmt, varName string, candidateFields []string, allFuncs map[string]*ast.FuncDecl, visited map[string]bool) []string {
	want := make(map[string]bool, len(candidateFields))
	for _, f := range candidateFields {
		want[f] = true
	}
	found := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			id, ok := node.X.(*ast.Ident)
			if ok && id.Name == varName && want[node.Sel.Name] {
				found[node.Sel.Name] = true
			}
		case *ast.CallExpr:
			callee, ok := node.Fun.(*ast.Ident) // plain identifier: same-package function call
			if !ok {
				return true
			}
			calleeFn, ok := allFuncs[callee.Name]
			if !ok || visited[callee.Name] || calleeFn.Type.Params == nil {
				return true
			}
			// Find which parameter position received varName unchanged, and
			// recurse using the callee's name for that position.
			argIdx := -1
			for i, arg := range node.Args {
				if id, ok := arg.(*ast.Ident); ok && id.Name == varName {
					argIdx = i
					break
				}
			}
			if argIdx == -1 {
				return true
			}
			paramName := paramNameAtIndex(calleeFn.Type.Params, argIdx)
			if paramName == "" {
				return true
			}
			nextVisited := make(map[string]bool, len(visited)+1)
			for k := range visited {
				nextVisited[k] = true
			}
			nextVisited[callee.Name] = true
			for _, f := range referencedFields(calleeFn.Body, paramName, candidateFields, allFuncs, nextVisited) {
				found[f] = true
			}
		}
		return true
	})
	out := make([]string, 0, len(found))
	for f := range found {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// paramNameAtIndex returns the identifier name of the idx'th parameter across
// a possibly-grouped parameter list (`func f(a, b models.X, c int)` — a and b
// share one field group), or "" if idx is out of range or that slot is
// unnamed.
func paramNameAtIndex(params *ast.FieldList, idx int) string {
	i := 0
	for _, field := range params.List {
		n := len(field.Names)
		if n == 0 { // unnamed parameter — counts as one slot
			n = 1
		}
		if idx < i+n {
			if len(field.Names) == 0 {
				return ""
			}
			return field.Names[idx-i].Name
		}
		i += n
	}
	return ""
}

// isCheckFuncName reports whether name matches ^check[A-Z]\w*$.
func isCheckFuncName(name string) bool {
	if !strings.HasPrefix(name, "check") || len(name) == len("check") {
		return false
	}
	r := name[len("check")]
	return r >= 'A' && r <= 'Z'
}

// modelsTypeName extracts "X" from a `models.X`, `*models.X`, or `[]models.X`
// type expression (checkCronQuality([]models.CronJob), checkAnacronSchedules,
// checkCgroupUnits all take a slice — []models.CronJob/AnacronJob/CgroupUnit
// have no unverified-signal field today, so this didn't change the candidate
// count when added, but a scan that silently excluded slice params would be
// a quiet blind spot the day one of those structs gains one). ok is false for
// anything else (a different package, a builtin) — the caller treats that as
// out of scope.
func modelsTypeName(expr ast.Expr) (string, bool) {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if arr, ok := expr.(*ast.ArrayType); ok {
		expr = arr.Elt
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok || pkgIdent.Name != "models" {
		return "", false
	}
	return sel.Sel.Name, true
}

// parseModelStructFields returns, for every `type X struct {...}` in dir's
// non-test .go files, the list of its (non-embedded) field names.
func parseModelStructFields(t *testing.T, fset *token.FileSet, dir string) map[string][]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	out := map[string][]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			var fields []string
			for _, f := range st.Fields.List {
				for _, fname := range f.Names { // skip embedded (no names)
					fields = append(fields, fname.Name)
				}
			}
			out[ts.Name.Name] = append(out[ts.Name.Name], fields...)
			return true
		})
	}
	return out
}

// packageDirForGovernanceTest resolves rel (a module-root-relative path like
// "internal/models") to an absolute directory, anchored on this test file's
// own path (runtime.Caller), not the process working directory — go test's
// CWD is the package directory, not the repo root.
func packageDirForGovernanceTest(t *testing.T, rel string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed to resolve this test file's path")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, rel)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find go.mod walking up from %s", thisFile)
		}
		dir = parent
	}
}
