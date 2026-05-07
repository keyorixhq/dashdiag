# DashDiag — Sprint 2, 3, and 4 Implementation Prompts
## Tasks 2.1 through 4.3
## Paste each block into Claude Code

---

## TASK 2.1 + 2.2 — dsd examples + dsd hook install
### No SPEC.md needed

Paste this into Claude Code:

```
1. Create cmd/examples.go (~50 lines, pure output, no collectors):

func init() { rootCmd.AddCommand(examplesCmd) }

var examplesCmd = &cobra.Command{
    Use:   "examples",
    Short: "Real-world usage workflows",
    RunE:  runExamples,
}

func init() { examplesCmd.Flags().Int("scenario", 0, "show one scenario (1-6)") }

func runExamples(cmd *cobra.Command, args []string) error {
    n, _ := cmd.Flags().GetInt("scenario")
    scenarios := []struct{ title, desc, commands string }{
        {
            "1. Incident triage",
            "Something is wrong. Find out what changed and document it.",
            "  dsd health\n  dsd health --diff\n  dsd health --story\n  dsd health --post-mortem \"API latency spike\"",
        },
        {
            "2. Pre-deploy check",
            "Verify system is healthy before pushing to production.",
            "  dsd health\n  dsd health deep",
        },
        {
            "3. Network investigation",
            "Connectivity issues or high latency.",
            "  dsd net\n  dsd net deep",
        },
        {
            "4. Share with team",
            "Share a snapshot in Slack without requiring install.",
            "  dsd health --share\n  dsd health --report --out report.md",
        },
        {
            "5. Kubernetes cluster",
            "Check pod health, OOM kills, and node conditions.",
            "  dsd k8s\n  dsd k8s deep",
        },
        {
            "6. Automate health checks",
            "Run dsd on SSH login, git push, or in CI pipelines.",
            "  dsd hook install",
        },
    }
    for i, s := range scenarios {
        if n != 0 && n != i+1 { continue }
        fmt.Printf("\n%s\n%s\n%s\n", s.title, s.desc, s.commands)
    }
    return nil
}

2. Create internal/init/detector.go:

package init_pkg  // use init_pkg to avoid conflict with Go's init()

func DetectServerProfile() string {
    // Parse /proc/[0-9]*/comm on Linux, ps aux on macOS
    // Return: "web", "database", "kubernetes", "proxmox", "general"
    procs := runningProcessNames()
    switch {
    case containsAny(procs, "nginx", "apache2", "caddy", "httpd"):
        return "web"
    case containsAny(procs, "postgres", "mysqld", "redis-server", "mongod"):
        return "database"
    case containsAny(procs, "kubelet"):
        return "kubernetes"
    case containsAny(procs, "pvecheckd", "pvedaemon"):
        return "proxmox"
    default:
        return "general"
    }
}

3. Create internal/init/firstrun.go:

func IsFirstRun() bool {
    home, _ := os.UserHomeDir()
    _, err := os.Stat(filepath.Join(home, ".dsd", "state.json"))
    return os.IsNotExist(err)
}

func RunWizard(mode output.OutputMode) error {
    profile := DetectServerProfile()
    fmt.Printf("Detected server type: %s\n", profile)
    chosen, err := tui.RunSingleSelect(
        "Confirm server profile (affects default thresholds):",
        []string{"web", "database", "kubernetes", "proxmox", "general"},
    )
    if err != nil { return nil } // wizard cancelled is not an error
    writeProfileConfig(chosen)
    fmt.Printf("✅ Profile saved to ~/.dsd.yaml\n\n")
    return nil
}

4. Create cmd/hook.go:

var hookCmd = &cobra.Command{Use: "hook", Short: "Manage shell and CI hooks"}
var hookInstallCmd = &cobra.Command{
    Use: "install", Short: "Install DashDiag hooks",
    RunE: runHookInstall,
}
func init() {
    rootCmd.AddCommand(hookCmd)
    hookCmd.AddCommand(hookInstallCmd)
    hookInstallCmd.Flags().Bool("dry-run", false, "show what would be written without writing")
}

6 options via tui.RunMultiSelect:
  "SSH login (append to ~/.bashrc or ~/.zshrc)"
  "Pre-deploy script (generate scripts/check-health.sh)"
  "Git pre-push hook (.git/hooks/pre-push)"
  "systemd timer (/etc/systemd/system/dsd-health.timer)"
  "GitHub Actions (.github/workflows/dsd-health.yml)"
  "Show commands only (no files written)"

SSH login snippet to append:
  # DashDiag health check on login (remove to disable)
  which dsd &>/dev/null && dsd health --plain --compact 2>/dev/null || true

--dry-run output:
  DRY RUN — no files will be written

  Would modify ~/.zshrc:
    + # DashDiag health check on login
    + which dsd &>/dev/null && dsd health --plain --compact 2>/dev/null || true

After install: state.HookInstalled = true; state.Save()
```

---

## TASK 3.1 + 3.2 — dsd net + dsd net deep + dsd services

Paste this into Claude Code:

```
1. Create internal/collectors/network_deep.go:
   Name: "NetworkDeep", Timeout: 30s
   All of network_quick PLUS:
   - 20-sample jitter: loop 20 pings with time.After spacing, compute stddev of RTTs
   - Bonds: check /proc/net/bonding/ directory, read status files
   - Ethtool: exec ethtool <iface> (graceful if not installed: skip silently)
   - Wireless: exec iw dev <iface> link (graceful if not installed)
   Progress note: "ℹ️  Traceroute only runs if problem detected"

2. Create cmd/net.go:
   func init() {
       rootCmd.AddCommand(netCmd)
       netCmd.AddCommand(netDeepCmd)
   }
   dsd net      → NetworkQuickCollector, progress "Network snapshot (~3s)"
   dsd net deep → NetworkDeepCollector, progress "Deep network analysis (~30s)"

3. Create internal/collectors/services.go:
   Name: "Services", Timeout: 10s
   Read config.Load().Services
   TCP: net.DialTimeout("tcp", "host:port", 5*time.Second)
   HTTP: http.Client{Timeout: 10s}.Get(url) — check status < 500
   Run all service checks concurrently
   Empty state (no services configured):
     Return ServiceInfo with empty slice — render shows guidance
   Return []models.ServiceInfo (one per configured service)

4. Create cmd/services.go:
   Empty state message in renderer:
     ℹ️  No services configured yet.
         Add to ~/.dsd.yaml:

         services:
           - name: nginx
             host: localhost
             port: 80
             protocol: http

         Or run: dsd init  to configure automatically.

Verify:
  ./dist/dsd net
  ./dist/dsd net deep
  ./dist/dsd services
```

---

## TASK 3.3 + 3.4 — Phase 1 complete verification + commit
### No SPEC.md needed

Paste this into Claude Code:

```
Run full Phase 1 verification. Fix any failures.

go build ./...
go vet ./...
go test ./... -race -count=1 -timeout 60s
make build

./dist/dsd health
./dist/dsd health --json | python3 -m json.tool
./dist/dsd health --plain
./dist/dsd health --diff
./dist/dsd health --since-deploy
./dist/dsd health --story
./dist/dsd health --post-mortem "phase 1 test"
./dist/dsd net
./dist/dsd services
./dist/dsd examples
./dist/dsd hook install --dry-run
./dist/dsd healt

bash scripts/smoke-test.sh

git add -A
git commit -m "feat: Phase 1 complete — dsd health, net, services all working"
git tag v0.3.0-phase1
```

---

## TASK 4.1 + 4.2 — --watch mode + --yaml output
### No SPEC.md needed

Paste this into Claude Code:

```
1. Wire --watch flag in cmd/health.go:

Add to healthCmd in init():
  healthCmd.Flags().Bool("watch", false, "refresh health check periodically")
  healthCmd.Flags().Duration("watch-interval", 60*time.Second, "refresh interval")

In runHealth(), after mode detection:
  watchFlag, _ := cmd.Flags().GetBool("watch")
  if watchFlag {
      interval, _ := cmd.Flags().GetDuration("watch-interval")
      return runWatch(ctx, interval, ctrCtx, cloudEnv, cfg, mode)
  }

func runWatch(ctx context.Context, interval time.Duration,
    ctrCtx platform.ContainerContext, cloudEnv platform.CloudEnvironment,
    cfg *config.Config, mode output.OutputMode) error {
    fmt.Fprintf(os.Stderr, "⚡ Watching (refresh every %s, Ctrl+C to exit)\n\n", interval)
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    var prevSnap *baseline.Snapshot
    for {
        results, insights := runHealthOnce(ctx, ctrCtx, cloudEnv, cfg)
        snap := baseline.BuildSnapshot(results, insights)
        if prevSnap == nil {
            render.NewRenderer(mode).PrintAll(results, insights)
        } else {
            diffs := baseline.ComputeDiff(prevSnap, snap)
            hasChanges := false
            for _, d := range diffs { if d.Changed { hasChanges = true; break } }
            if hasChanges {
                render.PrintDiff(prevSnap, snap, mode)
            } else {
                fmt.Printf("  ✅  No changes — %s\n", time.Now().Format("15:04:05"))
            }
        }
        prevSnap = snap
        select {
        case <-ctx.Done(): return nil
        case <-ticker.C:
        }
    }
}

2. Add ModeYAML to internal/output/tty.go:
   const ModeYAML OutputMode = 4
   Update DetectMode(): case "yaml" → return ModeYAML

3. Add YAML rendering in internal/render/json.go:
   func RenderYAML(results []runner.Result, insights []models.Insight) ([]byte, error) {
       // Same struct as RenderJSON but gopkg.in/yaml.v3
   }

4. Wire in runHealth():
   if mode == output.ModeYAML {
       data, _ := render.RenderYAML(results, insights)
       os.Stdout.Write(data)
       return nil
   }

Verify:
  ./dist/dsd health --yaml
  ./dist/dsd health --watch &; sleep 5; kill %1
```

---

## TASK 4.3 — Final integration + git tag
### No SPEC.md needed

Paste this into Claude Code:

```
Run complete end-to-end verification of every implemented feature.
Fix any failures before tagging.

./dist/dsd health
./dist/dsd health --json | python3 -m json.tool
./dist/dsd health --yaml
./dist/dsd health --plain
./dist/dsd health --diff
./dist/dsd health --since-deploy
./dist/dsd health --story
./dist/dsd health --post-mortem "final integration test"
./dist/dsd health --weekly
./dist/dsd health --watch & sleep 3 && kill %1
./dist/dsd net
./dist/dsd net deep
./dist/dsd services
./dist/dsd examples
./dist/dsd examples --scenario 1
./dist/dsd hook install --dry-run
./dist/dsd healt
./dist/dsd --help | grep "◆"

make test-all
bash scripts/smoke-test.sh

git add -A
git commit -m "feat: Sprint 4 complete — all core features implemented"
git tag v0.4.0
```

