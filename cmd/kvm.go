package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
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

	printKVMReport(info, elapsed)
	return nil
}

func printKVMReport(info *models.KVMInfo, elapsed time.Duration) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	if !info.Detected {
		fmt.Println()
		fmt.Println(render.StyleInfo.Render("ℹ️  libvirt not found — is KVM/libvirt installed and running?"))
		fmt.Println("   to install (RHEL/Fedora): dnf install qemu-kvm libvirt libvirt-client")
		fmt.Println("   to install (Debian/Ubuntu): apt install qemu-kvm libvirt-daemon-system")
		fmt.Println("   to start:   systemctl enable --now libvirtd")
		fmt.Println()
		fmt.Println(sep)
		fmt.Println(render.StyleInfo.Render("ℹ️  KVM not detected" + timing))
		return
	}

	verStr := ""
	if info.LibvirtVer != "" {
		verStr = fmt.Sprintf("  [libvirt %s / QEMU %s]", info.LibvirtVer, info.QEMUVer)
	}
	fmt.Printf("\n🖥️  KVM / libvirt%s\n", verStr)

	printKVMVMs(info)
	printKVMNetworks(info)
	printKVMPools(info)

	fmt.Println()
	fmt.Println(sep)
	issues := info.VMsCrashed + info.VMsDownAutostart + info.NetworksInactive +
		info.PoolsNearFull + info.PoolsInactive + info.DiskIOErrors + info.VMsPaused
	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("✅ KVM healthy. Checks passed%s", timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(
			fmt.Sprintf("⚠️  %d KVM concern(s) found%s", issues, timing)))
	}
}

func printKVMVMs(info *models.KVMInfo) {
	if len(info.VMs) == 0 {
		fmt.Printf("\n[VMs] — none defined\n")
		return
	}
	fmt.Printf("\n[VMs] — %d total (%d running)\n", len(info.VMs), info.VMsRunning)
	for _, vm := range info.VMs {
		icon := kvmVMIcon(vm)
		memStr := ""
		if vm.MaxMemMB > 0 {
			memStr = fmt.Sprintf("  %dMB RAM", vm.MaxMemMB)
		}
		autoStr := ""
		if vm.State == models.KVMShutOff && vm.AutoStart {
			autoStr = "  ⚠️  autostart=yes"
		}
		fmt.Printf("  %s %-20s %-10s%s%s\n",
			icon, vm.Name, string(vm.State), memStr, autoStr)
		if vm.DiskIOError {
			fmt.Printf("       ❌ disk I/O error recorded — to check: virsh domblkerror %s\n", vm.Name)
		}
		if vm.LastLogError != "" {
			fmt.Printf("       last log error: %s\n", vm.LastLogError)
		}
	}
}

func kvmVMIcon(vm models.KVMVM) string {
	switch vm.State {
	case models.KVMCrashed:
		return "❌"
	case models.KVMPaused:
		return "⚠️ "
	case models.KVMShutOff, models.KVMShutDown:
		if vm.AutoStart {
			return "⚠️ "
		}
		return "⏹ "
	default:
		return "✅"
	}
}

func printKVMNetworks(info *models.KVMInfo) {
	if len(info.Networks) == 0 {
		return
	}
	fmt.Printf("\n[Networks]\n")
	for _, n := range info.Networks {
		if n.State != "active" {
			fmt.Printf("  ⚠️  %-20s inactive\n", n.Name)
			continue
		}
		bridgeStr := ""
		if n.Bridge != "" {
			bIcon := "✅"
			if !n.BridgeUp {
				bIcon = "⚠️ "
			}
			bridgeStr = fmt.Sprintf("  %s %s", bIcon, n.Bridge)
		}
		fmt.Printf("  ✅  %-20s active%s\n", n.Name, bridgeStr)
	}
}

func printKVMPools(info *models.KVMInfo) {
	if len(info.StoragePools) == 0 {
		return
	}
	fmt.Printf("\n[Storage Pools]\n")
	for _, p := range info.StoragePools {
		if p.State != "active" {
			fmt.Printf("  ⚠️  %-20s inactive\n", p.Name)
			continue
		}
		icon := "✅"
		usedStr := ""
		if p.CapacityGB > 0 {
			if p.UsedPct >= 95 {
				icon = "❌"
			} else if p.UsedPct >= 85 {
				icon = "⚠️ "
			}
			usedStr = fmt.Sprintf("  %.1fGB free / %.1fGB  (%.0f%%)",
				p.AvailableGB, p.CapacityGB, p.UsedPct)
		}
		fmt.Printf("  %s  %-20s active%s\n", icon, p.Name, usedStr)
	}
}
