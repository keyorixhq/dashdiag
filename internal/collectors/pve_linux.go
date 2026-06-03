//go:build linux

package collectors

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// IsPVEHost returns true when this machine is a Proxmox VE host.
// Fast check — just tests for the pvedaemon binary.
func IsPVEHost() bool {
	_, err := os.Stat("/usr/bin/pvedaemon")
	return err == nil
}

// PVECollector checks Proxmox VE host health: subscription, cluster quorum,
// HA fencing, storage usage, and backup job status.
// Graceful no-op when not running on a Proxmox host.
type PVECollector struct{}

func NewPVECollector() *PVECollector { return &PVECollector{} }

func (c *PVECollector) Name() string { return "PVE" }

// Timeout covers ~11 sequential pvesh calls at ~0.8s each (pvesh spawns a Perl
// API client per call). Collectors cannot parallelize (the runner owns
// concurrency), so the budget must accommodate the full sequence.
func (c *PVECollector) Timeout() time.Duration { return 15 * time.Second }

func (c *PVECollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.PVEInfo{}

	// Quick Proxmox detection — pvedaemon binary must exist
	if _, err := os.Stat("/usr/bin/pvedaemon"); err != nil {
		return info, nil
	}
	info.IsPVE = true

	// Node identity — these work without root.
	info.PVEVersion = collectPVEVersion(ctx)
	info.KernelVersion = collectKernelVersion()

	// Root check — pvesh requires root
	if os.Getuid() != 0 {
		info.NeedsRoot = true
		// Still collect what we can without root
		info.Subscription = collectPVESubscriptionFile()
		return info, nil
	}

	// Node status — CPU% + uptime via pvesh
	info.CPUPct, info.UptimeSec = collectPVENodeStatus(ctx)

	// Subscription status
	info.Subscription = collectPVESubscription(ctx)

	// Cluster quorum + nodes
	info.ClusterName, info.QuorumOK, info.Nodes = collectPVECluster(ctx)

	// HA fencing
	info.HAFencingOK, info.HAFencingMsg = collectPVEHAFencing(ctx)

	// Storage usage
	info.Storages = collectPVEStorages(ctx)

	// VMs and LXC containers (collected before backups so the audit can map per-VM)
	info.Guests, info.RunningCount, info.StoppedCount, info.PausedCount = collectPVEGuests(ctx)

	// Backup tasks — global age + per-VM audit
	info.RecentBackups, info.BackupAgeDays, info.BackupStatuses = collectPVEBackups(ctx, info.Guests)

	// Resource overcommit
	info.TotalVCPUs, info.TotalMemGB = collectPVEResourceUsage(info.Guests)
	info.PhysicalCores = collectPhysicalCores()
	info.HostMemGB = collectHostMemGB()

	// Recent task errors (last 24h)
	info.TaskErrors = collectPVETaskErrors(ctx)

	// Network bridges
	info.Bridges = collectPVEBridges(ctx)

	return info, nil
}

// collectPVEVersion parses `pveversion -v` and extracts the pve-manager version.
// Output lines look like "pve-manager: 8.2.2 (running version: 8.2.2/...)" or,
// for plain `pveversion`, "pve-manager/8.2.2/<hash> (running kernel: ...)".
func collectPVEVersion(ctx context.Context) string {
	out, err := runCmd(ctx, "pveversion", "-v")
	if err != nil || strings.TrimSpace(out) == "" {
		// Fallback to plain pveversion (single line, slash-delimited)
		out, err = runCmd(ctx, "pveversion")
		if err != nil {
			return ""
		}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "pve-manager") {
			continue
		}
		return parsePVEManagerVersion(line)
	}
	return ""
}

// parsePVEManagerVersion extracts the version token from a pve-manager line,
// handling both "pve-manager: 8.2.2 (...)" and "pve-manager/8.2.2/<hash> (...)".
func parsePVEManagerVersion(line string) string {
	rest := strings.TrimPrefix(line, "pve-manager")
	switch {
	case strings.HasPrefix(rest, ":"):
		rest = strings.TrimSpace(strings.TrimPrefix(rest, ":"))
	case strings.HasPrefix(rest, "/"):
		rest = strings.TrimPrefix(rest, "/")
	}
	fields := strings.FieldsFunc(rest, func(r rune) bool { return r == ' ' || r == '/' })
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// collectKernelVersion reads the running kernel release (uname -r equivalent).
func collectKernelVersion() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease") // #nosec G304 -- hardcoded /proc path
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// collectPVENodeStatus reads CPU usage and uptime from the node status endpoint.
// The "cpu" field is a 0..1 fraction; multiply by 100 for a percentage.
func collectPVENodeStatus(ctx context.Context) (cpuPct float64, uptimeSec int64) {
	out, err := runCmd(ctx, "pvesh", "get", "/nodes/localhost/status", "--output-format", "json")
	if err != nil {
		return 0, 0
	}
	var result struct {
		CPU    float64 `json:"cpu"`
		Uptime int64   `json:"uptime"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return 0, 0
	}
	return result.CPU * 100, result.Uptime
}

// collectPVESubscription runs pvesh to get subscription status.
func collectPVESubscription(ctx context.Context) models.PVESubscription {
	out, err := runCmd(ctx, "pvesh", "get", "/nodes/localhost/subscription", "--output-format", "json")
	if err != nil {
		return collectPVESubscriptionFile()
	}
	var result struct {
		Status  string `json:"status"`
		Level   string `json:"level"`
		Product string `json:"product"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return collectPVESubscriptionFile()
	}
	return models.PVESubscription{
		Status:  result.Status,
		Level:   result.Level,
		Product: result.Product,
	}
}

// collectPVESubscriptionFile reads subscription status from the local file
// as a fallback when pvesh is unavailable or running without root.
func collectPVESubscriptionFile() models.PVESubscription {
	data, err := os.ReadFile("/etc/apt/auth.conf.d/pve.conf")
	if err != nil {
		// No subscription file — community/no subscription
		return models.PVESubscription{Status: "notfound"}
	}
	// File exists — has a subscription key configured
	if strings.Contains(string(data), "login") {
		return models.PVESubscription{Status: "active"}
	}
	return models.PVESubscription{Status: "unknown"}
}

// collectPVECluster reads cluster quorum and node status via pvesh.
func collectPVECluster(ctx context.Context) (name string, quorumOK bool, nodes []models.PVENode) {
	out, err := runCmd(ctx, "pvesh", "get", "/cluster/status", "--output-format", "json")
	if err != nil {
		// Single-node / no cluster — quorum is implicit
		return "", true, nil
	}

	var items []struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Quorate int    `json:"quorate"`
		Online  int    `json:"online"`
		Version string `json:"pve_version"`
	}
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		return "", true, nil
	}

	quorumOK = true
	for _, item := range items {
		switch item.Type {
		case "cluster":
			name = item.Name
			if item.Quorate == 0 {
				quorumOK = false
			}
		case "node":
			nodes = append(nodes, models.PVENode{
				Name:    item.Name,
				Online:  item.Online == 1,
				Version: item.Version,
			})
		}
	}
	return name, quorumOK, nodes
}

// collectPVEHAFencing checks HA fencing device status.
func collectPVEHAFencing(ctx context.Context) (ok bool, msg string) {
	out, err := runCmd(ctx, "pvesh", "get", "/cluster/ha/status/current", "--output-format", "json")
	if err != nil {
		// No HA configured — not a problem
		return true, ""
	}
	var result struct {
		Quorate int    `json:"quorate"`
		Mode    string `json:"mode"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return true, ""
	}
	if result.Mode == "error" || result.Mode == "fence" {
		return false, "HA is in " + result.Mode + " mode — check fencing device"
	}
	return true, ""
}

// collectPVEStorages reads storage usage from pvesh.
func collectPVEStorages(ctx context.Context) []models.PVEStorage {
	out, err := runCmd(ctx, "pvesh", "get", "/nodes/localhost/storage",
		"--output-format", "json")
	if err != nil {
		return nil
	}

	var items []struct {
		Storage string  `json:"storage"`
		Type    string  `json:"type"`
		Used    float64 `json:"used"`
		Total   float64 `json:"total"`
		Active  int     `json:"active"`
	}
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		return nil
	}

	var storages []models.PVEStorage
	for _, item := range items {
		s := models.PVEStorage{
			Name:    item.Storage,
			Type:    item.Type,
			UsedGB:  item.Used / (1024 * 1024 * 1024),
			TotalGB: item.Total / (1024 * 1024 * 1024),
			Active:  item.Active == 1,
		}
		if item.Total > 0 {
			s.UsedPct = item.Used / item.Total * 100
		}
		storages = append(storages, s)
	}
	return storages
}

// collectPVEBackups reads recent backup tasks from pvesh and determines both
// the global age of the last successful backup and a per-VM/CT backup audit.
// Templates are skipped silently from the per-VM audit.
func collectPVEBackups(ctx context.Context, guests []models.PVEGuest) (
	tasks []models.PVEBackupTask, ageDays int, statuses []models.PVEBackupStatus,
) {
	// 200 tasks gives enough history to age backups older than 30 days.
	out, err := runCmd(ctx, "pvesh", "get", "/nodes/localhost/tasks",
		"--output-format", "json",
		"--typefilter", "vzdump",
		"--limit", "200")
	if err != nil {
		// Fallback: scan backup log files (per-VM audit unavailable)
		return nil, collectPVEBackupAgeFromLogs(), nil
	}

	var items []struct {
		VMID    string  `json:"id"`
		Status  string  `json:"status"`
		EndTime float64 `json:"endtime"`
	}
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		return nil, -1, nil
	}

	ageDays = -1 // -1 = never
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	lastSuccess := time.Time{}
	lastOKByVM := make(map[int]time.Time) // most recent successful backup per VMID

	for _, item := range items {
		end := time.Unix(int64(item.EndTime), 0)
		vmid := 0
		if n, err := strconv.Atoi(item.VMID); err == nil {
			vmid = n
		}
		if end.After(cutoff) {
			tasks = append(tasks, models.PVEBackupTask{
				VMID:    vmid,
				Status:  item.Status,
				EndTime: int64(item.EndTime),
			})
		}
		if item.Status == "OK" {
			if end.After(lastSuccess) {
				lastSuccess = end
			}
			if end.After(lastOKByVM[vmid]) {
				lastOKByVM[vmid] = end
			}
		}
	}

	if !lastSuccess.IsZero() {
		ageDays = int(time.Since(lastSuccess).Hours() / 24)
	}
	statuses = backupAudit(guests, lastOKByVM)
	return tasks, ageDays, statuses
}

// backupAudit produces a per-VM/CT backup status from the last-successful-backup
// map. Templates are skipped silently. LastBackupDays is -1 when never backed up.
func backupAudit(guests []models.PVEGuest, lastOKByVM map[int]time.Time) []models.PVEBackupStatus {
	statuses := make([]models.PVEBackupStatus, 0, len(guests))
	for _, g := range guests {
		if g.IsTemplate {
			continue // templates are not expected to have backups
		}
		days := -1
		if t, ok := lastOKByVM[g.VMID]; ok && !t.IsZero() {
			days = int(time.Since(t).Hours() / 24)
		}
		statuses = append(statuses, models.PVEBackupStatus{
			VMID:           g.VMID,
			Name:           g.Name,
			LastBackupDays: days,
		})
	}
	return statuses
}

// collectPVEBackupAgeFromLogs scans /var/log/vzdump/ for recent backup logs.
func collectPVEBackupAgeFromLogs() int {
	entries, err := filepath.Glob("/var/log/vzdump/*.log")
	if err != nil || len(entries) == 0 {
		return -1
	}
	// Find the most recently modified log file
	var newest time.Time
	for _, e := range entries {
		fi, err := os.Stat(e)
		if err != nil {
			continue
		}
		// Only count logs that contain "Backup job finished successfully"
		f, err := os.Open(e) // #nosec G304
		if err != nil {
			continue
		}
		success := false
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "Backup job finished successfully") {
				success = true
				break
			}
		}
		f.Close() //nolint:errcheck
		if success && fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	if newest.IsZero() {
		return -1
	}
	return int(time.Since(newest).Hours() / 24)
}

// collectPVEGuests fetches VMs (qemu) and LXC containers from pvesh.
func collectPVEGuests(ctx context.Context) (guests []models.PVEGuest, running, stopped, paused int) {
	type guestRaw struct {
		VMID     int     `json:"vmid"`
		Name     string  `json:"name"`
		Status   string  `json:"status"`
		OnBoot   int     `json:"onboot"`
		CPUs     int     `json:"cpus"`
		MaxMem   float64 `json:"maxmem"`   // bytes
		Template int     `json:"template"` // 1 = template
	}
	for _, gtype := range []string{"qemu", "lxc"} {
		out, err := runCmd(ctx, "pvesh", "get", "/nodes/localhost/"+gtype, "--output-format", "json")
		if err != nil {
			continue
		}
		var raw []guestRaw
		if err := json.Unmarshal([]byte(out), &raw); err != nil {
			continue
		}
		for _, r := range raw {
			g := models.PVEGuest{
				VMID:       r.VMID,
				Name:       r.Name,
				Type:       gtype,
				Status:     r.Status,
				OnBoot:     r.OnBoot == 1,
				CPUs:       r.CPUs,
				MaxMemGB:   r.MaxMem / 1024 / 1024 / 1024,
				IsTemplate: r.Template == 1,
			}
			guests = append(guests, g)
			switch r.Status {
			case "running":
				running++
			case "paused":
				paused++
			default:
				stopped++
			}
		}
	}
	return
}

// collectPVEResourceUsage sums vCPUs and memory assigned to running guests.
func collectPVEResourceUsage(guests []models.PVEGuest) (vcpus int, memGB float64) {
	for _, g := range guests {
		if g.Status != "running" {
			continue
		}
		vcpus += g.CPUs
		memGB += g.MaxMemGB
	}
	return
}

// collectPhysicalCores reads the number of physical CPU cores from /proc/cpuinfo.
func collectPhysicalCores() int {
	data, err := os.ReadFile("/proc/cpuinfo") // #nosec G304
	if err != nil {
		return 0
	}
	coreSet := map[string]bool{}
	var physID, coreID string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "physical id") {
			physID = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(line, "core id") {
			coreID = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			coreSet[physID+":"+coreID] = true
		}
	}
	if len(coreSet) == 0 {
		return runtime.NumCPU()
	}
	return len(coreSet)
}

// collectHostMemGB reads total physical RAM from /proc/meminfo.
func collectHostMemGB() float64 {
	data, err := os.ReadFile("/proc/meminfo") // #nosec G304
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseFloat(fields[1], 64)
				return kb / 1024 / 1024
			}
		}
	}
	return 0
}

// collectPVETaskErrors reads the last 100 tasks and returns errors from the last 24h.
func collectPVETaskErrors(ctx context.Context) []models.PVETaskError {
	out, err := runCmd(ctx, "pvesh", "get", "/nodes/localhost/tasks",
		"--limit", "100", "--output-format", "json")
	if err != nil {
		return nil
	}
	var raw []struct {
		Type       string  `json:"type"`
		ID         string  `json:"id"`
		ExitStatus string  `json:"exitstatus"`
		Status     string  `json:"status"`
		StartTime  float64 `json:"starttime"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil
	}
	cutoff := float64(time.Now().Add(-24 * time.Hour).Unix())
	var errs []models.PVETaskError
	for _, t := range raw {
		if t.StartTime < cutoff {
			continue
		}
		exitOK := t.ExitStatus == "" || t.ExitStatus == "OK" || t.Status == "running"
		if exitOK {
			continue
		}
		startAt := ""
		if t.StartTime > 0 {
			startAt = time.Unix(int64(t.StartTime), 0).Format("15:04")
		}
		errs = append(errs, models.PVETaskError{
			Type:    t.Type,
			VMID:    t.ID,
			StartAt: startAt,
			Msg:     t.ExitStatus,
		})
	}
	return errs
}

// collectPVEBridges reads the node network config and returns one entry per
// bridge interface, with active/uplink/STP state for misconfiguration checks.
func collectPVEBridges(ctx context.Context) []models.PVEBridge {
	out, err := runCmd(ctx, "pvesh", "get", "/nodes/localhost/network", "--output-format", "json")
	if err != nil {
		return nil
	}
	var items []struct {
		Iface       string `json:"iface"`
		Type        string `json:"type"`
		Active      int    `json:"active"`
		BridgePorts string `json:"bridge_ports"`
	}
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		return nil
	}
	var bridges []models.PVEBridge
	for _, item := range items {
		if item.Type != "bridge" {
			continue
		}
		ports := strings.TrimSpace(item.BridgePorts)
		bridges = append(bridges, models.PVEBridge{
			Name:       item.Iface,
			Active:     item.Active == 1,
			HasUplink:  ports != "",
			Ports:      ports,
			STPEnabled: bridgeSTPEnabled(item.Iface),
		})
	}
	return bridges
}

// bridgeSTPEnabled reads /sys/class/net/<bridge>/bridge/stp_state (1=on, 0=off).
func bridgeSTPEnabled(name string) bool {
	clean := filepath.Base(name)                                              // defend against any path tricks in the iface name
	data, err := os.ReadFile("/sys/class/net/" + clean + "/bridge/stp_state") // #nosec G304 -- sysfs, name sanitised
	if err != nil {
		return false
	}
	return parseSTPState(string(data))
}

// parseSTPState reports whether a bridge stp_state value means STP is enabled.
// The sysfs file contains "1" (enabled) or "0" (disabled).
func parseSTPState(s string) bool {
	return strings.TrimSpace(s) == "1"
}

// CollectPVEPerf runs pveperf and parses the results. Exported for cmd/pve.go.
func CollectPVEPerf(ctx context.Context, path string) *models.PVEPerf {
	return collectPVEPerf(ctx, path)
}

// collectPVEPerf runs pveperf and parses the results.
func collectPVEPerf(ctx context.Context, path string) *models.PVEPerf {
	perf := &models.PVEPerf{Path: path}
	if _, err := os.Stat("/usr/bin/pveperf"); err != nil {
		return perf // not available
	}
	perf.Available = true
	out, err := runCmd(ctx, "pveperf", path)
	if err != nil && strings.TrimSpace(out) == "" {
		return perf
	}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// strip units: "469.31 MB/sec" → "469.31"
		numStr := strings.Fields(val)
		if len(numStr) == 0 {
			continue
		}
		num, err := strconv.ParseFloat(numStr[0], 64)
		if err != nil {
			continue
		}
		switch {
		case strings.HasPrefix(key, "CPU BOGOMIPS"):
			perf.CPUBogomips = num
		case strings.HasPrefix(key, "REGEX/SECOND"):
			perf.RegexPerSec = num
		case strings.HasPrefix(key, "BUFFERED READS"):
			perf.BufferedReadMB = num
		case strings.HasPrefix(key, "AVERAGE SEEK"):
			perf.AvgSeekMs = num
		case strings.HasPrefix(key, "FSYNCS/SECOND"):
			perf.FsyncsPerSec = num
		case strings.HasPrefix(key, "DNS EXT"):
			perf.DNSExtMs = num
		case strings.HasPrefix(key, "DNS INT"):
			perf.DNSIntMs = num
		}
	}
	return perf
}
