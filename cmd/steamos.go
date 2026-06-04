package cmd

import (
	"context"
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
	rootCmd.AddCommand(steamosCmd)
	steamosCmd.Flags().Bool("deep", false, "deep mode: gamescope/rauc logs, Proton/shader/flatpak sizes, BIOS")
}

var steamosCmd = &cobra.Command{
	Use:   "steamos",
	Short: "Steam Deck / SteamOS health — RAUC slots, rootfs, session, /var, Wi-Fi",
	RunE:  runSteamOS,
}

func runSteamOS(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	deep, _ := cmd.Flags().GetBool("deep")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	col := collectors.Collector(collectors.NewSteamOSCollector())
	if deep {
		col = collectors.NewSteamOSDeepCollector()
	}

	p := output.NewCommandProgress("SteamOS health", 8*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{col}) {
		p.Step(r.Name)
		result = r
	}

	elapsed := p.Elapsed()
	info, ok := result.Data.(*models.SteamOSInfo)
	if !ok || info == nil {
		return result.Err
	}

	recordResultSeverity([]runner.Result{result}) // BUG-022: honour 0/1/2 exit contract

	if mode == output.ModeJSON {
		return outputJSON(os.Stdout, info)
	}

	printSteamOSReport(info, elapsed)
	return nil
}

func printSteamOSReport(info *models.SteamOSInfo, elapsed time.Duration) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	if !info.Detected {
		fmt.Println()
		fmt.Println(render.StyleInfo.Render("ℹ️  Not a SteamOS / Steam Deck system — `dsd steamos` only applies there."))
		fmt.Println("   On a Steam Deck this checks RAUC slots, rootfs read-only state,")
		fmt.Println("   the Gamescope session, /var + /home space, and Wi-Fi.")
		fmt.Println()
		fmt.Println(sep)
		fmt.Println(render.StyleInfo.Render("ℹ️  SteamOS not detected" + timing))
		return
	}

	fmt.Println("\n🎮 SteamOS")
	printSteamOSSystem(info)
	printSteamOSRAUC(info)
	printSteamOSSession(info)
	printSteamOSStorage(info)
	printSteamOSNetwork(info)
	printSteamOSRemotePlay(info)
	if info.Deep {
		printSteamOSDeep(info)
	}

	fmt.Println()
	fmt.Println(sep)
	if c := steamOSConcernCount(info); c == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("✅ SteamOS healthy. Checks passed%s", timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("⚠️  %d SteamOS concern(s) found%s", c, timing)))
	}
}

func printSteamOSSystem(info *models.SteamOSInfo) {
	fmt.Println("\n[System]")
	printSteamOSDevice(info)
	ver := info.Version
	if ver == "" {
		ver = "unknown"
	}
	channel := info.Channel
	if channel == "" {
		channel = "unknown channel"
	} else {
		channel += " channel"
	}
	build := ""
	if info.BuildID != "" {
		build = fmt.Sprintf("  (BUILD_ID: %s)", info.BuildID)
	}
	fmt.Printf("  ✅ SteamOS %s  %s%s\n", ver, channel, build)
	if info.ChannelConfigMissing {
		fmt.Println("  ⚠️  steamos-atomupd client.conf missing — updater channel unknown")
	}

	switch {
	case !info.ReadonlyKnown:
		fmt.Println("  ℹ️  steamos-readonly: status unavailable")
	case info.ReadonlyEnabled:
		fmt.Println("  ✅ steamos-readonly: enabled (rootfs protected)")
	default:
		fmt.Println("  ❌ steamos-readonly: DISABLED (rootfs writable — next update will overwrite changes)")
	}
}

// printSteamOSDevice renders the device-identity + Secure Boot lines (Spec 17a).
func printSteamOSDevice(info *models.SteamOSInfo) {
	if info.DeviceProductRaw == "" && info.DeviceName == "" {
		return
	}
	switch {
	case info.DeviceName == "":
		// no DMI read
	case !info.DeviceRecognised:
		fmt.Printf("  ℹ️  Device: %s (DMI: %q) — unrecognised; thresholds may not be accurate\n",
			info.DeviceName, info.DeviceProductRaw)
	default:
		fmt.Printf("  ✅ Device: %s (%s)\n", info.DeviceName, info.DeviceProductRaw)
	}

	switch {
	case !info.SecureBootApplicable:
		fmt.Println("  ✅ Secure Boot: n/a (Steam Deck firmware)")
	case info.SecureBootEnabled == nil:
		fmt.Println("  ℹ️  Secure Boot: EFI not available")
	case *info.SecureBootEnabled:
		fmt.Println("  ⚠️  Secure Boot: ENABLED — USB recovery requires a BIOS change first")
	default:
		fmt.Println("  ✅ Secure Boot: disabled")
	}
}

func printSteamOSRAUC(info *models.SteamOSInfo) {
	fmt.Println("\n[RAUC update slots]")
	if !info.RAUCAvailable {
		fmt.Println("  ℹ️  rauc status unavailable")
		return
	}
	fmt.Printf("  %s Booted slot:   %s  (boot status: %s)\n",
		raucIcon(info.RAUCBootedStatus), orDash(info.RAUCBootedSlot), orDash(info.RAUCBootedStatus))
	fmt.Printf("  %s Inactive slot: %s  (boot status: %s)\n",
		raucIcon(info.RAUCInactiveStatus), orDash(info.RAUCInactiveSlot), orDash(info.RAUCInactiveStatus))
	if strings.EqualFold(info.RAUCInactiveStatus, "bad") {
		fmt.Printf("     → no rollback available; to fix: sudo rauc status mark-good %s\n", info.RAUCInactiveSlot)
	}
}

func printSteamOSSession(info *models.SteamOSInfo) {
	fmt.Println("\n[Session]")
	mode := info.SessionMode
	if mode == "" {
		mode = "unknown"
	}
	fmt.Printf("  ℹ️  Mode: %s\n", mode)
	fmt.Printf("  %s gamescope-session: %s\n", activeIcon(info.GamescopeActive), activeWord(info.GamescopeActive))
	fmt.Printf("  %s steam-launcher:    %s\n", activeIcon(info.SteamLauncherActive), activeWord(info.SteamLauncherActive))
	if info.SessionMode == "gamemode" && !info.GamescopeActive {
		fmt.Println("     ❌ Game Mode but gamescope-session inactive — session likely crashed")
	}
}

func printSteamOSStorage(info *models.SteamOSInfo) {
	fmt.Println("\n[Storage]")
	fmt.Printf("  %s /var:  %.0f / %.0f MB  (%.0f%% used)\n",
		usageIcon(info.VarUsedPct, 70, 85), info.VarUsedMB, info.VarTotalMB, info.VarUsedPct)
	fmt.Printf("  %s /home: %.0f / %.0f GB  (%.0f%% used)\n",
		usageIcon(info.HomeUsedPct, 85, 95), info.HomeUsedGB, info.HomeTotalGB, info.HomeUsedPct)
}

func printSteamOSNetwork(info *models.SteamOSInfo) {
	fmt.Println("\n[Network]")
	backend := info.WifiBackend
	if backend == "" {
		backend = "unknown"
	}
	note := " (default mode)"
	if info.WifiDevMode {
		note = " (dev-mode workaround — not the iwd default)"
	}
	fmt.Printf("  ✅ Wi-Fi: %s%s\n", backend, note)
	switch {
	case !info.UpdateServerKnown:
		fmt.Println("  ℹ️  SteamOS update server: not tested")
	case info.UpdateServerReachable:
		fmt.Printf("  ✅ SteamOS update server: reachable (%dms)\n", info.UpdateServerLatencyMs)
	default:
		fmt.Println("  ⚠️  SteamOS update server: unreachable")
	}
}

// printSteamOSRemotePlay renders the [Remote Play] section (Spec 22 Part A).
func printSteamOSRemotePlay(info *models.SteamOSInfo) {
	rp := info.RemotePlay
	if rp == nil {
		return
	}
	fmt.Println("\n[Remote Play]")
	fmt.Println("  Ports bound:")
	for _, p := range rp.Ports {
		label := fmt.Sprintf("%s %d", strings.ToUpper(p.Protocol), p.Port)
		switch {
		case p.Bound:
			who := p.Process
			if who == "" {
				who = "bound"
			} else if p.PID > 0 {
				who = fmt.Sprintf("%s (PID %d)", p.Process, p.PID)
			}
			fmt.Printf("  ✅ %-10s %s\n", label, who)
		case p.Optional:
			fmt.Printf("  ℹ️  %-10s not bound (VR — optional)\n", label)
		default:
			fmt.Printf("  ❌ %-10s not bound\n", label)
		}
	}

	switch {
	case !rp.FirewallKnown:
		fmt.Println("  Firewall: not readable (need root for nft/iptables)")
	case rp.FirewallBlocking:
		fmt.Println("  ⚠️  Firewall: a rule may block a Remote Play port — run: nft list ruleset")
	default:
		fmt.Println("  ✅ Firewall: no blocking rules found")
	}

	switch {
	case !rp.ARPChecked:
		fmt.Println("  ℹ️  LAN peer visibility: not checked (recent boot or no gateway)")
	case rp.APIsolationSuspected:
		fmt.Println("  ⚠️  LAN peer visibility: 0 peers — AP client isolation may be active")
	default:
		fmt.Printf("  ✅ LAN peer visibility: %d peer(s) in ARP cache\n", rp.LANPeersVisible)
	}
}

func printSteamOSDeep(info *models.SteamOSInfo) {
	fmt.Println("\n[Deep]")
	if info.ProtonPrefixCount > 0 || info.CompatDataGB > 0 {
		fmt.Printf("  Proton prefixes: %d  (compatdata %.1f GB)\n", info.ProtonPrefixCount, info.CompatDataGB)
	}
	if info.ShaderCacheGB > 0 {
		icon := "✅"
		if info.ShaderCacheGB > 10 {
			icon = "⚠️ "
		}
		fmt.Printf("  %s Shader cache: %.1f GB\n", icon, info.ShaderCacheGB)
	}
	if info.FlatpakAppCount > 0 || info.FlatpakDataGB > 0 {
		icon := "✅"
		if info.FlatpakDataGB > 20 {
			icon = "⚠️ "
		}
		fmt.Printf("  %s Flatpak: %d app(s), %.1f GB\n", icon, info.FlatpakAppCount, info.FlatpakDataGB)
	}
	if info.BIOSVersion != "" {
		fmt.Printf("  BIOS: %s\n", info.BIOSVersion)
	}
	for _, e := range info.GamescopeErrors {
		fmt.Printf("  gamescope: %s\n", e)
	}
	if info.RAUCLastLog != "" {
		fmt.Printf("  rauc (last): %s\n", info.RAUCLastLog)
	}
}

// steamOSConcernCount counts the conditions the heuristics treat as WARN/CRIT,
// for the human summary line (the precise severity drives the exit code).
func steamOSConcernCount(info *models.SteamOSInfo) int {
	n := 0
	if info.RAUCAvailable && strings.EqualFold(info.RAUCBootedStatus, "bad") {
		n++
	}
	if info.RAUCAvailable && strings.EqualFold(info.RAUCInactiveStatus, "bad") {
		n++
	}
	if info.ReadonlyKnown && !info.ReadonlyEnabled {
		n++
	}
	if info.ChannelConfigMissing {
		n++
	}
	if info.SessionMode == "gamemode" && !info.GamescopeActive {
		n++
	}
	if info.SecureBootApplicable && info.SecureBootEnabled != nil && *info.SecureBootEnabled {
		n++
	}
	if info.VarUsedPct >= 70 {
		n++
	}
	if info.HomeUsedPct >= 85 {
		n++
	}
	if info.UpdateServerKnown && !info.UpdateServerReachable {
		n++
	}
	if info.ShaderCacheGB > 10 {
		n++
	}
	if info.FlatpakDataGB > 20 {
		n++
	}
	if rp := info.RemotePlay; rp != nil {
		for _, p := range rp.Ports {
			if !p.Optional && !p.Bound {
				n++
				break
			}
		}
		if rp.FirewallBlocking {
			n++
		}
		if rp.ARPChecked && rp.APIsolationSuspected {
			n++
		}
	}
	return n
}

// ── small render helpers ───────────────────────────────────────────────────

func raucIcon(status string) string {
	if strings.EqualFold(status, "bad") {
		return "❌"
	}
	if status == "" {
		return "ℹ️ "
	}
	return "✅"
}

func usageIcon(pct, warn, crit float64) string {
	switch {
	case pct >= crit:
		return "❌"
	case pct >= warn:
		return "⚠️ "
	default:
		return "✅"
	}
}

func activeIcon(active bool) string {
	if active {
		return "✅"
	}
	return "⚠️ "
}

func activeWord(active bool) string {
	if active {
		return "active"
	}
	return "inactive"
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
