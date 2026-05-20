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

func (c *PVECollector) Name() string           { return "PVE" }
func (c *PVECollector) Timeout() time.Duration { return 8 * time.Second }

func (c *PVECollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.PVEInfo{}

	// Quick Proxmox detection — pvedaemon binary must exist
	if _, err := os.Stat("/usr/bin/pvedaemon"); err != nil {
		return info, nil
	}
	info.IsPVE = true

	// Root check — pvesh requires root
	if os.Getuid() != 0 {
		info.NeedsRoot = true
		// Still collect what we can without root
		info.Subscription = collectPVESubscriptionFile()
		return info, nil
	}

	// Subscription status
	info.Subscription = collectPVESubscription(ctx)

	// Cluster quorum + nodes
	info.ClusterName, info.QuorumOK, info.Nodes = collectPVECluster(ctx)

	// HA fencing
	info.HAFencingOK, info.HAFencingMsg = collectPVEHAFencing(ctx)

	// Storage usage
	info.Storages = collectPVEStorages(ctx)

	// Backup tasks — last 7 days
	info.RecentBackups, info.BackupAgeDays = collectPVEBackups(ctx)

	// VMs and LXC containers
	info.Guests, info.RunningCount, info.StoppedCount, info.PausedCount = collectPVEGuests(ctx)

	// Resource overcommit
	info.TotalVCPUs, info.TotalMemGB = collectPVEResourceUsage(info.Guests)
	info.PhysicalCores = collectPhysicalCores()
	info.HostMemGB = collectHostMemGB()

	// Recent task errors (last 24h)
	info.TaskErrors = collectPVETaskErrors(ctx)

	return info, nil
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

// collectPVEBackups reads recent backup tasks from pvesh and determines
// the age of the last successful backup in days.
func collectPVEBackups(ctx context.Context) (tasks []models.PVEBackupTask, ageDays int) {
	// First try pvesh task list
	out, err := runCmd(ctx, "pvesh", "get", "/nodes/localhost/tasks",
		"--output-format", "json",
		"--typefilter", "vzdump",
		"--limit", "50")
	if err != nil {
		// Fallback: scan backup log files
		return nil, collectPVEBackupAgeFromLogs()
	}

	var items []struct {
		VMID    string  `json:"id"`
		Status  string  `json:"status"`
		EndTime float64 `json:"endtime"`
	}
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		return nil, -1
	}

	ageDays = -1 // -1 = never
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	lastSuccess := time.Time{}

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
		if item.Status == "OK" && end.After(lastSuccess) {
			lastSuccess = end
		}
	}

	if !lastSuccess.IsZero() {
		ageDays = int(time.Since(lastSuccess).Hours() / 24)
	}
	return tasks, ageDays
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
		VMID   int     `json:"vmid"`
		Name   string  `json:"name"`
		Status string  `json:"status"`
		OnBoot int     `json:"onboot"`
		CPUs   int     `json:"cpus"`
		MaxMem float64 `json:"maxmem"` // bytes
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
				VMID:     r.VMID,
				Name:     r.Name,
				Type:     gtype,
				Status:   r.Status,
				OnBoot:   r.OnBoot == 1,
				CPUs:     r.CPUs,
				MaxMemGB: r.MaxMem / 1024 / 1024 / 1024,
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
