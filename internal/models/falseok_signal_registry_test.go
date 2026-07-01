package models

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The "unverified signal" surface: struct-field names (usually bool) that encode
// "we could NOT measure this" — the input to the false-OK bug class (a green OK
// rendered when nothing was actually checked; see cmd/falseok_verdict_test.go and
// the recurring fleet-review fixes). This test is a COMPLETENESS TRIPWIRE, not a
// correctness proof: it fails when a NEW such field appears in internal/models
// without a line in guardedUnverifiedSignals, forcing the author to consciously
// decide how it is guarded (a standalone-renderer case in
// cmd/falseok_verdict_test.go, or a note that it only feeds a health heuristic
// that folds to INFO/WARN). It does NOT prove the guard is correct — that is the
// per-case tests' job. Why it exists: #575/#576 regressed because a false-OK fix
// landed in the heuristic but the matching field's RENDERER path was silently left
// unguarded, and nothing flagged the omission.
var unverifiedSignalRe = regexp.MustCompile(`(Verified|Unverified|Unreadable|Queried|Reachable|ScanFailed|ReadFailed|NeedsRoot|NeedRoot|ScanOK)$`)

// guardedUnverifiedSignals maps "TypeName.FieldName" → how that signal is
// accounted for (the test/heuristic that prevents a green OK when it is set). Add a
// line when you add such a field. A note is a factual pointer, not a correctness
// certificate — the linked test is.
var guardedUnverifiedSignals = map[string]string{
	// Standalone renderers that can show an all-clear — guarded case-by-case in
	// cmd/falseok_verdict_test.go (the renderer must not print its green line when
	// the signal is unset).
	"K8sInfo.APIReachable":                "cmd/falseok_verdict_test.go (k8s renderer) + analysis/pve_apireachable_test.go",
	"CronInfo.FailureScanOK":              "cmd/falseok_verdict_test.go (cron) + analysis/cron_logs_unverified_test.go",
	"LogsInfo.ErrorCountUnverified":       "cmd/falseok_verdict_test.go (logs) + analysis/cron_logs_unverified_test.go",
	"LogsInfo.NeedsRoot":                  "cmd/falseok_verdict_test.go (logs non-root)",
	"LogsInfo.ErrorScanFailed":            "analysis/cron_logs_unverified_test.go (scan-failed → not 'none')",
	"ServicesDeepInfo.FailedUnitsQueried": "cmd/falseok_verdict_test.go (services deep)",
	"CVEAllResult.ScanFailed":             "cmd/falseok_verdict_test.go (cve) + collectors/cve_stale_metadata_test.go",

	// dsd security — renderer shares health's verdict via the heuristic.
	"SecurityInfo.NeedsRoot":           "analysis/heuristics_security_full_test.go + cmd/security_falseok_test.go",
	"SecurityInfo.PortsNeedRoot":       "analysis/heuristics_security_full_test.go (ports → 'run as root')",
	"SecurityInfo.ShadowUnreadable":    "analysis/mac_shadow_unverified_test.go + cmd/security_falseok_test.go",
	"SecurityInfo.SSHConfigUnreadable": "cis/ssh_unverified_test.go + cmd/security_falseok_test.go",
	"SecurityInfo.FirewallUnreadable":  "collectors/firewall_barename_linux_test.go (nft unreadable → INFO)",

	// Storage — heuristic folds an unreadable read to INFO/WARN, never OK.
	"CephInfo.NeedsRoot":            "analysis/heuristics_round3_test.go (configured+non-root → INFO, not false 'unreachable' CRIT)",
	"DiskInfo.ZFSListReadFailed":    "analysis/zfs_btrfs_unverified_test.go",
	"ZFSInfo.ListReadFailed":        "analysis/zfs_btrfs_unverified_test.go",
	"ZFSPool.StatusReadFailed":      "analysis/zfs_btrfs_unverified_test.go + heuristics_security_storage_test.go",
	"BtrfsVolume.DevReadUnverified": "collectors/btrfs_linux_test.go + analysis/heuristics_round2_test.go (BUG-070)",
	"LVMInfo.LVReadFailed":          "analysis/san_unverified_test.go",
	"LVMInfo.VGReadFailed":          "analysis/san_unverified_test.go",
	"LVMInfo.PVReadFailed":          "analysis/san_unverified_test.go",
	"LVMInfo.RaidReadFailed":        "analysis/heuristics_round7_test.go",
	"DRBDInfo.Unverified":           "analysis/san_unverified_test.go (DRBD 9 non-root → INFO 'needs root', not silent omission)",
	"ISCSIInfo.NeedsRoot":           "analysis/san_unverified_test.go (active sessions unreadable non-root → INFO, not silent)",

	// PVE — API/section verified flags; folded by the PVE heuristic.
	"PVEInfo.APIReachable":     "analysis/pve_apireachable_test.go",
	"PVEInfo.NeedsRoot":        "analysis/pve_apireachable_test.go + pve_unverified_test.go",
	"PVEInfo.StoragesVerified": "analysis/pve_unverified_test.go",
	"PVEInfo.TasksVerified":    "analysis/pve_unverified_test.go",
	"PVEInfo.BackupVerified":   "analysis/pve_unverified_test.go + heuristics_round5_test.go",
	"PVEInfo.HAVerified":       "analysis/pve_unverified_test.go",

	// Cloud / virt / other — heuristic folds the unmeasured state to INFO/WARN.
	"AWSInfo.EBSNeedsRoot":              "analysis/heuristics_aws_test.go (non-root EBS read → INFO)",
	"AWSInfo.EBSReadFailed":             "analysis/heuristics_aws_test.go (sibling of EBSNeedsRoot)",
	"KVMInfo.VMsUnreadable":             "collectors/kvm_pve_test.go + analysis/heuristics_round4_test.go",
	"GPUDevice.Unreadable":              "analysis (gpu all-zero/unreadable → not OK); see memory gpu-allzero-falseok-deferred",
	"NFSMount.ServerReachable":          "analysis (NFS reachability heuristic, net deep)",
	"CloudInitInfo.StatusUnverified":    "analysis/firmware_cloudinit_unverified_test.go",
	"SteamOSInfo.UpdateServerReachable": "analysis/steamos_test.go + heuristics_round9_test.go",
	"ServiceResult.Reachable":           "service-collector heuristic (DEGRADED when unreachable; analysis/heuristics_round9_test.go)",

	// RHEL/Oracle maintenance — heuristic folds the unmeasured state to INFO, never OK.
	"ServiceRestartInfo.NeedsRoot":    "analysis/heuristics_maintenance_test.go (non-root partial /proc scan → INFO 'partial', not a clean OK)",
	"KspliceInfo.CheckUnverified":     "analysis/heuristics_maintenance_test.go (uptrack status unread → INFO 'could not be read', not OK)",
	"KernelPatchInfo.CheckUnverified": "analysis/heuristics_maintenance_test.go + collectors/maintenance_linux_test.go (BUG-088: SUSE zypp lock held the whole budget → INFO 'could not be determined', never a silent drop or 'Kernel OK')",

	// Hardware RAID controller CLIs are root-only; unread output must never read healthy.
	"HWRaidInfo.NeedsRoot":  "analysis/heuristics_hwraid_test.go (TestCheckHWRaidHonestDegradation: controller CLI root-gated → INFO 're-run as root', never a clean OK or WARN/CRIT over unread state)",
	"HWRaidInfo.ReadFailed": "analysis/heuristics_hwraid_test.go (TestCheckHWRaidHonestDegradation: CLI output unparseable → INFO 'treat as UNVERIFIED, not healthy')",
}

func TestUnverifiedSignalFieldsAllRegistered(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read internal/models: %v", err)
	}

	fset := token.NewFileSet()
	found := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, 0)
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
			for _, f := range st.Fields.List {
				for _, fname := range f.Names { // skip embedded (no names)
					if unverifiedSignalRe.MatchString(fname.Name) {
						found[ts.Name.Name+"."+fname.Name] = true
					}
				}
			}
			return true
		})
	}

	var unregistered, stale []string
	for key := range found {
		if _, ok := guardedUnverifiedSignals[key]; !ok {
			unregistered = append(unregistered, key)
		}
	}
	for key := range guardedUnverifiedSignals {
		if !found[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(unregistered)
	sort.Strings(stale)

	if len(unregistered) > 0 {
		t.Errorf("%d unverified-signal field(s) are not registered in guardedUnverifiedSignals:\n  %s\n\n"+
			"Each encodes a 'could not measure' state. Register it with a note on how a green OK is "+
			"prevented when it is set — add a standalone-renderer case in cmd/falseok_verdict_test.go if "+
			"the field has a renderer that can show an all-clear, else note the heuristic that folds it to "+
			"INFO/WARN. (Completeness tripwire — see this file's doc comment.)",
			len(unregistered), strings.Join(unregistered, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("%d registry entr(y/ies) no longer exist in internal/models (remove them):\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}
}
