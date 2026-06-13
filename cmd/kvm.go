package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/cvedata"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	rootCmd.AddCommand(kvmCmd)
	kvmCmd.Flags().Bool("deep", false, "deep mode: full XML config check for non-running VMs")
}

var kvmCmd = &cobra.Command{
	Use:   "kvm",
	Short: "KVM/libvirt health — VMs, networks, storage pools, disk errors",
	RunE:  runKVM,
}

func runKVM(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	deep, _ := cmd.Flags().GetBool("deep")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	col := collectors.NewKVMCollector()
	if deep {
		col = collectors.NewKVMDeepCollector()
	}

	p := output.NewCommandProgress("KVM health", 15*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{col}) {
		p.Step(r.Name)
		result = r
	}

	elapsed := p.Elapsed()
	info, ok := result.Data.(*models.KVMInfo)
	if !ok || info == nil {
		return result.Err
	}

	if mode == output.ModeJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(info)
		return nil
	}

	printKVMReport(info, elapsed, mode)
	return nil
}

func printKVMReport(info *models.KVMInfo, elapsed time.Duration, mode output.OutputMode) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	if !info.Detected {
		fmt.Println()
		fmt.Println(render.StyleInfo.Render(asciiOr("info", "ℹ️  ", mode) + "libvirt not found — is KVM/libvirt installed and running?"))
		if isNixOS(cvedata.DetectDistroID()) {
			// NixOS installs and enables libvirtd declaratively; the rebuild
			// also starts the service, so no separate systemctl step.
			fmt.Println("   to install: set in configuration.nix: virtualisation.libvirtd.enable = true;")
			fmt.Println("   then apply:  sudo nixos-rebuild switch")
		} else {
			fmt.Println("   to install (RHEL/Fedora): dnf install qemu-kvm libvirt libvirt-client")
			fmt.Println("   to install (Debian/Ubuntu): apt install qemu-kvm libvirt-daemon-system")
			fmt.Println("   to start:   " + analysis.PlatformServiceCmd("systemctl enable --now libvirtd"))
		}
		fmt.Println()
		fmt.Println(sep)
		fmt.Println(render.StyleInfo.Render(asciiOr("info", "ℹ️  ", mode) + "KVM not detected" + timing))
		return
	}

	verStr := ""
	if info.LibvirtVer != "" {
		verStr = fmt.Sprintf("  [libvirt %s / QEMU %s]", info.LibvirtVer, info.QEMUVer)
	}
	fmt.Printf("\n🖥️  KVM / libvirt%s\n", verStr)

	printKVMVMs(info, mode)
	printKVMNetworks(info, mode)
	printKVMPools(info, mode)

	fmt.Println()
	fmt.Println(sep)
	issues := info.VMsCrashed + info.VMsDownAutostart + info.NetworksInactive +
		info.PoolsNearFull + info.PoolsInactive + info.DiskIOErrors + info.VMsPaused
	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("%sKVM healthy. Checks passed%s", asciiOr("ok", "✅ ", mode), timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(
			fmt.Sprintf("%s%d KVM concern(s) found%s", asciiOr("warn", "⚠️  ", mode), issues, timing)))
	}
}

func printKVMVMs(info *models.KVMInfo, mode output.OutputMode) {
	if len(info.VMs) == 0 {
		fmt.Printf("\n[VMs] — none defined\n")
		return
	}
	fmt.Printf("\n[VMs] — %d total (%d running)\n", len(info.VMs), info.VMsRunning)
	for _, vm := range info.VMs {
		icon := kvmVMIcon(vm, mode)
		memStr := ""
		if vm.MaxMemMB > 0 {
			memStr = fmt.Sprintf("  %dMB RAM", vm.MaxMemMB)
		}
		autoStr := ""
		if vm.State == models.KVMShutOff && vm.AutoStart {
			autoStr = "  " + asciiOr("warn", "⚠️  ", mode) + "autostart=yes"
		}
		fmt.Printf("  %s %-20s %-10s%s%s\n",
			icon, vm.Name, string(vm.State), memStr, autoStr)
		if vm.DiskIOError {
			fmt.Printf("       %sdisk I/O error recorded — to check: virsh domblkerror %s\n", asciiOr("fail", "❌ ", mode), vm.Name)
		}
		if vm.LastLogError != "" {
			fmt.Printf("       last log error: %s\n", vm.LastLogError)
		}
	}
}

func kvmVMIcon(vm models.KVMVM, mode output.OutputMode) string {
	switch vm.State {
	case models.KVMCrashed:
		return asciiOr("fail", "❌", mode)
	case models.KVMPaused:
		return asciiOr("warn", "⚠️ ", mode)
	case models.KVMShutOff, models.KVMShutDown:
		if vm.AutoStart {
			return asciiOr("warn", "⚠️ ", mode)
		}
		return asciiOr("off", "⏹ ", mode)
	default:
		return asciiOr("ok", "✅", mode)
	}
}

func printKVMNetworks(info *models.KVMInfo, mode output.OutputMode) {
	if len(info.Networks) == 0 {
		return
	}
	fmt.Printf("\n[Networks]\n")
	for _, n := range info.Networks {
		if n.State != "active" {
			fmt.Printf("  %s %-20s inactive\n", asciiOr("warn", "⚠️ ", mode), n.Name)
			continue
		}
		bridgeStr := ""
		if n.Bridge != "" {
			bIcon := asciiOr("ok", "✅", mode)
			if !n.BridgeUp {
				bIcon = asciiOr("warn", "⚠️ ", mode)
			}
			bridgeStr = fmt.Sprintf("  %s %s", bIcon, n.Bridge)
		}
		fmt.Printf("  %s  %-20s active%s\n", asciiOr("ok", "✅", mode), n.Name, bridgeStr)
	}
}

func printKVMPools(info *models.KVMInfo, mode output.OutputMode) {
	if len(info.StoragePools) == 0 {
		return
	}
	fmt.Printf("\n[Storage Pools]\n")
	for _, p := range info.StoragePools {
		if p.State != "active" {
			fmt.Printf("  %s %-20s inactive\n", asciiOr("warn", "⚠️ ", mode), p.Name)
			continue
		}
		icon := asciiOr("ok", "✅", mode)
		usedStr := ""
		if p.CapacityGB > 0 {
			if p.UsedPct >= 95 {
				icon = asciiOr("fail", "❌", mode)
			} else if p.UsedPct >= 85 {
				icon = asciiOr("warn", "⚠️ ", mode)
			}
			usedStr = fmt.Sprintf("  %.1fGB free / %.1fGB  (%.0f%%)",
				p.AvailableGB, p.CapacityGB, p.UsedPct)
		}
		fmt.Printf("  %s  %-20s active%s\n", icon, p.Name, usedStr)
	}
}
