//go:build linux

package collectors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	pveCmdPvesh   = "pvesh"
	pveFmtJSON    = "json"
	pveCmdGet     = "get"
	pveFlagOutFmt = "--output-format"
	pveFldStatus  = "status"
	pveFldType    = "type"
	pveValRunning = "running"
	pveGuestQEMU  = "qemu"
	pveGuestLXC   = "lxc"
)

// IsPVEHost returns true when this machine is a Proxmox VE host.
// Fast check — just tests for the pvedaemon binary.
func IsPVEHost() bool {
	return fileExists("/usr/bin/pvedaemon")
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
	if !fileExists("/usr/bin/pvedaemon") {
		return info, nil
	}
	info.IsPVE = true

	// Node identity — these work without root.
	info.PVEVersion = collectPVEVersion(ctx)
	info.KernelVersion = collectKernelVersion()

	// Root check — pvesh requires root
	if getuid() != 0 {
		info.NeedsRoot = true
		// Still collect what we can without root
		info.Subscription = collectPVESubscriptionFile()
		return info, nil
	}

	// Node status — CPU% + uptime via pvesh
	info.CPUPct, info.UptimeSec = collectPVENodeStatus(ctx)

	// Subscription status
	info.Subscription = collectPVESubscription(ctx)

	// Cluster quorum + nodes. APIReachable doubles as the canonical "pvesh is
	// responding" probe: if it fails, every collection below is empty/unreliable.
	info.ClusterName, info.QuorumOK, info.Nodes, info.APIReachable = collectPVECluster(ctx)

	// HA fencing
	info.HAFencingOK, info.HAFencingMsg, info.HAVerified = collectPVEHAFencing(ctx)

	// Storage usage
	info.Storages, info.StoragesVerified = collectPVEStorages(ctx)

	// VMs and LXC containers (collected before backups so the audit can map per-VM)
	info.Guests, info.RunningCount, info.StoppedCount, info.PausedCount = collectPVEGuests(ctx)

	// Backup tasks — global age + per-VM audit
	info.RecentBackups, info.BackupAgeDays, info.BackupStatuses, info.BackupVerified = collectPVEBackups(ctx, info.Guests)

	// Resource overcommit
	info.TotalVCPUs, info.TotalMemGB = collectPVEResourceUsage(info.Guests)
	info.PhysicalCores = collectPhysicalCores()
	info.HostMemGB = collectHostMemGB()

	// Recent task errors (last 24h)
	info.TaskErrors, info.TasksVerified = collectPVETaskErrors(ctx)

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
	data, err := readFile("/proc/sys/kernel/osrelease") // #nosec G304 -- hardcoded /proc path
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// collectPVENodeStatus reads CPU usage and uptime from the node status endpoint.
// The "cpu" field is a 0..1 fraction; multiply by 100 for a percentage.
func collectPVENodeStatus(ctx context.Context) (cpuPct float64, uptimeSec int64) {
	out, err := runCmd(ctx, pveCmdPvesh, pveCmdGet, "/nodes/localhost/status", pveFlagOutFmt, pveFmtJSON)
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
	out, err := runCmd(ctx, pveCmdPvesh, pveCmdGet, "/nodes/localhost/subscription", pveFlagOutFmt, pveFmtJSON)
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
	data, err := readFile("/etc/apt/auth.conf.d/pve.conf")
	if err != nil {
		// No subscription file — community/no subscription
		return models.PVESubscription{Status: "notfound"}
	}
	// File exists — a subscription key is CONFIGURED, but the file's presence does
	// NOT prove the subscription is currently active: an expired-but-still-configured
	// subscription leaves this file in place. Returning secValActive here (the old
	// behaviour) let a wedged subscription API silently flip a genuinely EXPIRED
	// subscription to active and suppress the CRIT (FALSE_OK_SWEEP #40). Report
	// "unverified" so the analysis layer surfaces it honestly.
	if strings.Contains(string(data), "login") {
		return models.PVESubscription{Status: "unverified"}
	}
	return models.PVESubscription{Status: "unknown"}
}

// collectPVECluster reads cluster quorum and node status via pvesh.
func collectPVECluster(ctx context.Context) (name string, quorumOK bool, nodes []models.PVENode, reachable bool) {
	out, err := runCmd(ctx, pveCmdPvesh, pveCmdGet, "/cluster/status", pveFlagOutFmt, pveFmtJSON)
	if err != nil {
		// pvesh failed — API/pmxcfs unreachable. NOT the same as a standalone node:
		// a standalone node returns exit 0 with a single `node` item (verified live
		// on PVE 9.1). reachable=false so the analysis layer reports "not verified"
		// instead of assuming quorum is implicitly OK (a false-OK).
		return "", false, nil, false
	}

	var items []struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Quorate int    `json:"quorate"`
		Online  int    `json:"online"`
		Version string `json:"pve_version"`
	}
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		return "", false, nil, false
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
	return name, quorumOK, nodes, true
}

// collectPVEHAFencing checks HA fencing/manager status. The endpoint returns a JSON
// ARRAY of status entries — on a node without HA configured, just the quorum entry
// ([{"id":"quorum",pveFldStatus:"OK",...}]); with HA, additional lrm/crm/service entries.
// (The previous single-object struct never matched this array, so fence detection
// was dead and always fell through to a clean OK.) verified is false only when the
// API answered but the body was unparseable; a runCmd error means the endpoint is
// absent (HA not available) and stays verified — nothing to read.
func collectPVEHAFencing(ctx context.Context) (ok bool, msg string, verified bool) {
	out, err := runCmd(ctx, pveCmdPvesh, pveCmdGet, "/cluster/ha/status/current", pveFlagOutFmt, pveFmtJSON)
	if err != nil {
		return true, "", true
	}
	var entries []struct {
		ID     string `json:"id"`
		Type   string `json:"type"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		// The API responded but we couldn't parse it — fencing state NOT verified.
		return true, "", false
	}
	// Conservatively flag only an explicit error/fence state on any entry; an idle
	// node's quorum entry is "OK" and healthy HA services are "started"/pveValRunning.
	for _, e := range entries {
		s := strings.ToLower(e.Status)
		if strings.Contains(s, "fence") || strings.Contains(s, "error") {
			return false, fmt.Sprintf("HA %s %q is in %q state", e.Type, e.ID, e.Status), true
		}
	}
	return true, "", true
}

// collectPVEStorages reads storage usage from pvesh. verified is false when the
// query failed or was unparseable, so the analysis layer can say "storage health
// not verified" instead of silently reporting no storage problems.
func collectPVEStorages(ctx context.Context) (storagesOut []models.PVEStorage, verified bool) {
	out, err := runCmd(ctx, pveCmdPvesh, pveCmdGet, "/nodes/localhost/storage",
		pveFlagOutFmt, pveFmtJSON)
	if err != nil {
		return nil, false
	}

	var items []struct {
		Storage string  `json:"storage"`
		Type    string  `json:"type"`
		Used    float64 `json:"used"`
		Total   float64 `json:"total"`
		Active  int     `json:"active"`
		Enabled int     `json:"enabled"`
	}
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		return nil, false
	}

	var storages []models.PVEStorage
	for _, item := range items {
		s := models.PVEStorage{
			Name:    item.Storage,
			Type:    item.Type,
			UsedGB:  item.Used / (1024 * 1024 * 1024),
			TotalGB: item.Total / (1024 * 1024 * 1024),
			Active:  item.Active == 1,
			Enabled: item.Enabled == 1,
		}
		if item.Total > 0 {
			s.UsedPct = item.Used / item.Total * 100
		}
		storages = append(storages, s)
	}
	return storages, true
}

// collectPVEBackups reads recent backup tasks from pvesh and determines both
// the global age of the last successful backup and a per-VM/CT backup audit.
// Templates are skipped silently from the per-VM audit.
//
// The per-VM audit is driven by scanning the vzdump dump directories, because
// `vzdump --all` produces a single bulk task with no per-VM id field — the only
// place the VMID appears is the archive filename. pvesh task records are used
// only as a fallback (e.g. single-guest backups when no archive is on disk).
func collectPVEBackups(ctx context.Context, guests []models.PVEGuest) (
	tasks []models.PVEBackupTask, ageDays int, statuses []models.PVEBackupStatus, verified bool,
) {
	dumpByVM := scanBackupDumpDir() // authoritative per-VM source

	// 200 tasks gives enough history to age backups older than 30 days.
	out, err := runCmd(ctx, pveCmdPvesh, pveCmdGet, "/nodes/localhost/tasks",
		pveFlagOutFmt, pveFmtJSON,
		"--typefilter", "vzdump",
		"--limit", "200")
	if err != nil {
		// pvesh unavailable — derive everything from the dump dir + log scan. We
		// consider backups "verified" only if that on-disk fallback actually found
		// something; otherwise BackupAgeDays stays -1 with no statuses and the analysis
		// layer must say "not verified" rather than stay silent (FALSE_OK_SWEEP #8).
		ageDays = collectPVEBackupAgeFromLogs()
		if ageDays < 0 {
			if newest := newestBackupTime(dumpByVM); !newest.IsZero() {
				ageDays = int(time.Since(newest).Hours() / 24)
			}
		}
		audit := backupAudit(guests, dumpByVM)
		// backupAudit always emits one status per non-template guest (LastBackupDays=-1
		// when nothing found), so len(audit)>0 is true whenever guests exist — NOT a
		// signal that the disk fallback found anything. Verified must reflect actual
		// disk evidence (dumpByVM non-empty), not guest count, or a host with zero
		// vzdump archives reads as "verified: no backup issues" (FALSE_OK_SWEEP #8).
		verifiedFromDisk := ageDays >= 0 || len(dumpByVM) > 0
		return nil, ageDays, audit, verifiedFromDisk
	}

	tasks, ageDays, pveshByVM := parsePVEBackupTasks(out)

	// Per-VM: dump-dir scan wins; fall back to per-VM task records.
	perVM := dumpByVM
	if len(perVM) == 0 {
		perVM = pveshByVM
	}
	// Global age: if tasks gave nothing, derive from the newest archive on disk.
	if ageDays < 0 {
		if newest := newestBackupTime(perVM); !newest.IsZero() {
			ageDays = int(time.Since(newest).Hours() / 24)
		}
	}
	// The vzdump task list query succeeded, so backup health WAS verified (even an
	// empty list is a real answer: no backups configured).
	return tasks, ageDays, backupAudit(guests, perVM), true
}

// parsePVEBackupTasks parses the vzdump task list JSON into recent tasks (last
// 7 days), the global age in days of the last successful backup (-1 = none),
// and the most recent successful backup time per VMID.
func parsePVEBackupTasks(out string) (tasks []models.PVEBackupTask, ageDays int, byVM map[int]time.Time) {
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
	byVM = make(map[int]time.Time)

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
			if end.After(byVM[vmid]) {
				byVM[vmid] = end
			}
		}
	}

	if !lastSuccess.IsZero() {
		ageDays = int(time.Since(lastSuccess).Hours() / 24)
	}
	return tasks, ageDays, byVM
}

// backupDumpDirs are the candidate vzdump output directories, in priority order.
var backupDumpDirs = []string{
	"/mnt/data/dump",          // primary (local-hdd on the test node)
	"/var/lib/vz/dump",        // default local storage
	"/var/lib/pve/local/dump", // alternate
}

// vzdumpArchiveExts are the compression suffixes vzdump archives can carry.
var vzdumpArchiveExts = []string{
	"vma.zst", "tar.zst", "vma.lzo", "tar.lzo", "vma.gz", "tar.gz",
}

// scanBackupDumpDir scans the known vzdump output directories for backup
// archives and returns the most recent backup time per VMID. This is reliable
// even for `vzdump --all`, since the VMID is embedded in each archive filename.
// File mtime is used as the backup time (robust regardless of filename format).
func scanBackupDumpDir() map[int]time.Time {
	return scanBackupDumpDirs(backupDumpDirs)
}

// scanBackupDumpDirs is the testable core of scanBackupDumpDir.
func scanBackupDumpDirs(dirs []string) map[int]time.Time {
	result := make(map[int]time.Time)
	for _, dir := range dirs {
		for _, ext := range vzdumpArchiveExts {
			matches, err := glob(filepath.Join(dir, "vzdump-*."+ext))
			if err != nil {
				continue
			}
			for _, path := range matches {
				vmid, ok := parseVzdumpVMID(filepath.Base(path))
				if !ok {
					continue
				}
				fi, err := statFile(path)
				if err != nil {
					continue
				}
				if mt := fi.ModTime; mt.After(result[vmid]) {
					result[vmid] = mt
				}
			}
		}
	}
	return result
}

// parseVzdumpVMID extracts the VMID from a vzdump archive filename.
// Format: vzdump-<qemu|lxc>-<vmid>-<date>-<time>.<ext>
//
//	e.g. "vzdump-qemu-100-2024_06_03-19_16_09.vma.zst" → 100
func parseVzdumpVMID(name string) (int, bool) {
	if !strings.HasPrefix(name, "vzdump-") {
		return 0, false
	}
	parts := strings.Split(name, "-")
	// parts: ["vzdump", pveGuestQEMU|pveGuestLXC, "<vmid>", "<date>", "<time>.<ext>"]
	if len(parts) < 4 {
		return 0, false
	}
	if parts[1] != pveGuestQEMU && parts[1] != pveGuestLXC {
		return 0, false
	}
	vmid, err := strconv.Atoi(parts[2])
	if err != nil || vmid <= 0 {
		return 0, false
	}
	return vmid, true
}

// newestBackupTime returns the most recent time across a per-VM backup map.
func newestBackupTime(byVM map[int]time.Time) time.Time {
	var newest time.Time
	for _, t := range byVM {
		if t.After(newest) {
			newest = t
		}
	}
	return newest
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
	entries, err := glob("/var/log/vzdump/*.log")
	if err != nil || len(entries) == 0 {
		return -1
	}
	// Find the most recently modified log file
	var newest time.Time
	for _, e := range entries {
		fi, err := statFile(e)
		if err != nil {
			continue
		}
		// Only count logs that contain "Backup job finished successfully"
		f, err := openFile(e) // #nosec G304
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
		if err := scanner.Err(); err != nil {
			// Partial/failed read of this log — skip it like the other
			// per-file failures above rather than treating it as success.
			f.Close() //nolint:errcheck
			continue
		}
		f.Close() //nolint:errcheck
		if success && fi.ModTime.After(newest) {
			newest = fi.ModTime
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
	for _, gtype := range []string{pveGuestQEMU, pveGuestLXC} {
		out, err := runCmd(ctx, pveCmdPvesh, pveCmdGet, "/nodes/localhost/"+gtype, pveFlagOutFmt, pveFmtJSON)
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
			case pveValRunning:
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
		if g.Status != pveValRunning {
			continue
		}
		vcpus += g.CPUs
		memGB += g.MaxMemGB
	}
	return
}

// collectPhysicalCores reads the number of physical CPU cores from /proc/cpuinfo.
func collectPhysicalCores() int {
	data, err := readFile("/proc/cpuinfo") // #nosec G304
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
	data, err := readFile("/proc/meminfo") // #nosec G304
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return parseFloat(fields[1]) / 1024 / 1024
			}
		}
	}
	return 0
}

// collectPVETaskErrors reads the last 100 tasks and returns errors from the last 24h.
// collectPVETaskErrors reads recent failed tasks. verified is false when the task
// list could not be read or parsed, so a nil result is reported as "task log
// unreadable" rather than a clean "no recent failures".
func collectPVETaskErrors(ctx context.Context) (errsOut []models.PVETaskError, verified bool) {
	out, err := runCmd(ctx, pveCmdPvesh, pveCmdGet, "/nodes/localhost/tasks",
		"--limit", "100", pveFlagOutFmt, pveFmtJSON)
	if err != nil {
		return nil, false
	}
	var raw []struct {
		Type       string  `json:"type"`
		ID         string  `json:"id"`
		ExitStatus string  `json:"exitstatus"`
		Status     string  `json:"status"`
		StartTime  float64 `json:"starttime"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, false
	}
	cutoff := float64(time.Now().Add(-24 * time.Hour).Unix())
	var errs []models.PVETaskError
	for _, t := range raw {
		if t.StartTime < cutoff {
			continue
		}
		exitOK := t.ExitStatus == "" || t.ExitStatus == "OK" || t.Status == pveValRunning
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
	return errs, true
}

// collectPVEBridges reads the node network config and returns one entry per
// bridge interface, with active/uplink/STP state for misconfiguration checks.
func collectPVEBridges(ctx context.Context) []models.PVEBridge {
	out, err := runCmd(ctx, pveCmdPvesh, pveCmdGet, "/nodes/localhost/network", pveFlagOutFmt, pveFmtJSON)
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
	clean := filepath.Base(name)                                           // defend against any path tricks in the iface name
	data, err := readFile("/sys/class/net/" + clean + "/bridge/stp_state") // #nosec G304 -- sysfs, name sanitised
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
	if !fileExists("/usr/bin/pveperf") {
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
		num, ok := parseFiniteFloat(numStr[0])
		if !ok {
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
