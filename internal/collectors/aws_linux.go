//go:build linux

package collectors

import (
	"context"
	"encoding/binary"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

const (
	awsDrvENA      = "ena"
	awsPlatformEC2 = "ec2"
	awsSvcSSMAgent = "amazon-ssm-agent"
)

// AWSCollector reports guest-side health for a Linux EC2 instance: ENA network
// allowance throttling, EBS volume performance throttling, IMDS security posture,
// Amazon Time Sync, the SSM agent, and the spot rebalance recommendation. All work
// is gated behind AWSGuestAvailable() so it is zero-cost and silent on every host
// that is not an EC2 instance. Scope is strictly guest-side, no AWS API credentials.
type AWSCollector struct{}

func NewAWSCollector() *AWSCollector { return &AWSCollector{} }

func (c *AWSCollector) Name() string { return "AWS" }

// 5s budget: the ENA/EBS reads are local and fast; the only slow paths are the IMDS
// probes (each capped at 2s, and instant on a real instance) and the single ~1s
// delta sample, which only happens when a first-pass throttle counter is non-zero.
func (c *AWSCollector) Timeout() time.Duration { return 5 * time.Second }

// AWSGuestAvailable reports whether this host is a Linux EC2 instance. Cheap gate
// (same shape as VMwareGuestAvailable): world-readable DMI vendor strings, or the
// awsPlatformEC2 hypervisor-UUID prefix as a fallback — no root, no command execution.
func AWSGuestAvailable() bool {
	return isAWSGuest(
		readFileTrimmedLocal(filepath.Join(dmiIDDir, "sys_vendor")),
		readFileTrimmedLocal(filepath.Join(dmiIDDir, "bios_vendor")),
		readFileTrimmedLocal(filepath.Join(dmiIDDir, "product_name")),
		readFileTrimmedLocal("/sys/hypervisor/uuid"),
	)
}

// isAWSGuest matches EC2's DMI signatures. sys_vendor is "Amazon EC2" on Nitro
// instances; bios_vendor is "Amazon EC2". Older Xen instances expose an "ec2…"
// hypervisor UUID instead, so that is checked as a fallback.
func isAWSGuest(sysVendor, biosVendor, productName, hypervisorUUID string) bool {
	hay := strings.ToLower(sysVendor + " " + biosVendor + " " + productName)
	if strings.Contains(hay, "amazon ec2") {
		return true
	}
	return strings.HasPrefix(strings.ToLower(hypervisorUUID), awsPlatformEC2)
}

func (c *AWSCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.AWSInfo{IsEC2: true}

	// --- driver/kernel telemetry: first snapshot ---
	ena1 := enaRead(ctx)
	ebs1, ebsMeta := ebsRead(ctx)
	info.EBSReadAttempted = ebsMeta.attempted
	info.EBSNeedsRoot = ebsMeta.needsRoot
	info.EBSReadFailed = ebsMeta.failed

	// Only pay for a second snapshot when a counter is already non-zero (so there is
	// something to disambiguate) and we are live — a cumulative-since-boot counter on
	// its own can't tell an active throttle from a stale historical one. Skipped under
	// replay: identical recorded reads would just yield a zero delta anyway.
	var enaDelta map[string]map[string]uint64
	var ebsDelta map[string]ebsRaw
	if (enaAnyNonzero(ena1) || ebsAnyNonzero(ebs1)) && !isReplaySource() {
		if sleepCtx(ctx, time.Second) {
			ena2 := enaRead(ctx)
			ebs2, _ := ebsRead(ctx)
			enaDelta = enaComputeDelta(ena1, ena2)
			ebsDelta = ebsComputeDelta(ebs1, ebs2)
			info.Sampled = true
		}
	}
	info.ENA = enaAssemble(ena1, enaDelta)
	info.EBS = ebsAssemble(ebs1, ebsDelta)

	// --- instance metadata + posture (IMDS) ---
	info.InstanceType = awsInstanceType(ctx)
	info.IMDSChecked, info.IMDSv1Enabled = awsIMDSv1Open(ctx)
	info.RebalanceChecked, info.RebalanceRecommended = awsRebalance(ctx)

	// --- local daemon state ---
	info.TimeSyncChecked, info.UsesAmazonTimeSync = amazonTimeSyncConfigured()
	info.SSMInstalled, info.SSMRunning = ssmState(ctx)

	// --- full-coverage tail (recognition/context) ---
	info.NitroEnclavesPresent, info.NitroEnclavesAllocatorRuns = nitroEnclaveState(ctx)
	info.ENAExpressChecked, info.ENAExpressActive = enaExpressState(ctx)

	return info, nil
}

// ---------- Nitro Enclaves ----------

// nitroEnclaveState reports whether Nitro Enclaves are available on this instance.
// /dev/nitro_enclaves exists only when the instance was launched with enclave options
// and the nitro_enclaves driver is loaded; the allocator service reserves the enclave's
// CPUs and memory. Informational — surfaces an isolated-compute facility, never a fault.
func nitroEnclaveState(ctx context.Context) (present, allocatorRunning bool) {
	if !fileExists("/dev/nitro_enclaves") {
		return false, false
	}
	present = true
	if out, err := runCmd(ctx, "systemctl", "is-active", "nitro-enclaves-allocator"); err == nil &&
		strings.TrimSpace(out) == "active" {
		allocatorRunning = true
	}
	return present, allocatorRunning
}

// ---------- ENA Express (SRD) ----------

// enaExpressState reports whether ENA Express is enabled and carrying traffic. It reads
// the ENA interfaces' `ethtool -S` independently of the throttle path so it cannot
// perturb the allowance-counter delta logic. checked is false when no ENA interface was
// readable, so an unread NIC never reads as "no ENA Express".
func enaExpressState(ctx context.Context) (checked, active bool) {
	ifaces := enaInterfaces()
	if len(ifaces) == 0 {
		return false, false
	}
	for _, iface := range ifaces {
		out, err := runCmd(ctx, "ethtool", "-S", iface)
		if err != nil {
			continue
		}
		checked = true
		if enaSRDActive(out) {
			return true, true
		}
	}
	return checked, false
}

// enaSRDActive reports whether ENA Express SRD packet counters are present AND non-zero
// in `ethtool -S` output — SRD is enabled and actually carrying traffic. A garbled or
// non-numeric value is ignored (don't ingest hostile tool output).
func enaSRDActive(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "ena_srd_tx_pkts", "ena_srd_rx_pkts":
			if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64); err == nil && n > 0 {
				return true
			}
		}
	}
	return false
}

// isReplaySource is true when collectors are reading from a replay bundle rather
// than the live system, so timing-dependent behaviour (the delta sample sleep) can
// be skipped — replay can't reproduce live throttling timing.
func isReplaySource() bool {
	_, ok := curSource().(*source.Replay)
	return ok
}

// sleepCtx sleeps d, returning false if ctx is cancelled first (so the caller skips
// the second snapshot rather than running it after the deadline).
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// ---------- ENA network allowance counters ----------

// enaAllowanceKeys maps the ethtool stat names ENA exposes to the canonical short
// names used in ENAStats. Only these five are read — they are the allowance-exceeded
// counters that signal silent network shaping/drops.
var enaAllowanceKeys = map[string]string{
	"bw_in_allowance_exceeded":     "bw_in",
	"bw_out_allowance_exceeded":    "bw_out",
	"pps_allowance_exceeded":       "pps",
	"conntrack_allowance_exceeded": "conntrack",
	"linklocal_allowance_exceeded": "linklocal",
}

// enaRead returns, per ENA interface, the current allowance-exceeded counters
// (canonical-short-name -> value). Interfaces whose driver is not awsDrvENA are skipped.
func enaRead(ctx context.Context) map[string]map[string]uint64 {
	out := map[string]map[string]uint64{}
	for _, iface := range enaInterfaces() {
		stats, err := runCmd(ctx, "ethtool", "-S", iface)
		if err != nil {
			continue
		}
		if counters := parseENAStats(stats); len(counters) > 0 {
			out[iface] = counters
		}
	}
	return out
}

// enaInterfaces lists non-loopback interfaces whose kernel driver is awsDrvENA.
func enaInterfaces() []string {
	drivers, _ := collectNICDrivers("/sys/class/net")
	var ifaces []string
	for iface, drv := range drivers {
		if strings.EqualFold(drv, awsDrvENA) {
			ifaces = append(ifaces, iface)
		}
	}
	return ifaces
}

// parseENAStats pulls the five allowance-exceeded counters out of `ethtool -S`
// output ("     key: value" lines), keyed by canonical short name. A line whose
// value is not an unsigned integer is skipped (don't ingest garbled output).
func parseENAStats(out string) map[string]uint64 {
	counters := map[string]uint64{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		short, want := enaAllowanceKeys[strings.TrimSpace(k)]
		if !want {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		if err != nil {
			continue
		}
		counters[short] = n
	}
	return counters
}

func enaAnyNonzero(m map[string]map[string]uint64) bool {
	for _, counters := range m {
		for _, v := range counters {
			if v > 0 {
				return true
			}
		}
	}
	return false
}

// enaComputeDelta returns, per interface, the increase from the first to the second
// snapshot (saturating at 0) — the allowance-exceeded events during the sample window.
func enaComputeDelta(first, second map[string]map[string]uint64) map[string]map[string]uint64 {
	delta := map[string]map[string]uint64{}
	for iface, c1 := range first {
		c2 := second[iface]
		d := map[string]uint64{}
		for k, before := range c1 {
			d[k] = subSat(c2[k], before)
		}
		delta[iface] = d
	}
	return delta
}

func enaAssemble(totals, delta map[string]map[string]uint64) []models.ENAStats {
	if len(totals) == 0 {
		return nil
	}
	out := make([]models.ENAStats, 0, len(totals))
	for iface, counters := range totals {
		s := models.ENAStats{Iface: iface, Total: counters}
		if delta != nil {
			s.Active = delta[iface]
		}
		out = append(out, s)
	}
	sortENA(out)
	return out
}

func sortENA(s []models.ENAStats) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].Iface < s[j-1].Iface; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ---------- EBS NVMe performance log page (0xD0) ----------

const (
	ebsStatsLogPageID = "0xd0"
	ebsStatsMagic     = 0x3C23B510 // first u32 of the Amazon EBS stats log page
)

type ebsRaw struct {
	volIOPS, volTP, instIOPS, instTP uint64
}

type ebsReadMeta struct {
	attempted bool
	needsRoot bool
	failed    bool
}

// ebsRead returns, per EBS NVMe device, the four performance-exceeded counters
// (microseconds), plus metadata about whether the read was attempted and why it may
// have failed. A device whose log page lacks the EBS magic is dropped (not trusted).
func ebsRead(ctx context.Context) (map[string]ebsRaw, ebsReadMeta) {
	out := map[string]ebsRaw{}
	var meta ebsReadMeta
	devices := ebsDevices()
	if len(devices) == 0 {
		return out, meta
	}
	meta.attempted = true
	for _, dev := range devices {
		raw, err := runCmd(ctx, "nvme", "get-log", "/dev/"+dev,
			"--log-id="+ebsStatsLogPageID, "--log-len=4096", "--raw-binary")
		if err != nil {
			if os.Geteuid() != 0 {
				meta.needsRoot = true // non-root can't read the vendor log page — couldn't measure
			} else {
				meta.failed = true
			}
			continue
		}
		if parsed, ok := parseEBSLogPage([]byte(raw)); ok {
			out[dev] = parsed
		} else {
			meta.failed = true // present but unparseable/no magic — don't pass it as healthy
		}
	}
	return out, meta
}

// ebsDevices lists EBS NVMe block devices by their sysfs model string. Instance-store
// NVMe ("Amazon EC2 NVMe Instance Storage") is deliberately excluded — the 0xD0 page
// is the EBS performance page.
func ebsDevices() []string {
	entries, err := readDirEntries("/sys/block")
	if err != nil {
		return nil
	}
	var devs []string
	for _, e := range entries {
		dev := e.Name()
		if !strings.HasPrefix(dev, "nvme") {
			continue
		}
		model := readFileTrimmedLocal(filepath.Join("/sys/block", dev, "device", "model"))
		if isEBSModel(model) {
			devs = append(devs, dev)
		}
	}
	return devs
}

// isEBSModel reports whether an NVMe device's sysfs model string identifies an EBS
// volume ("Amazon Elastic Block Store"). Instance-store NVMe ("Amazon EC2 NVMe
// Instance Storage") is deliberately NOT matched — the 0xD0 page is EBS-specific —
// mirroring the "Instance Storage" split in platform.detectAWSStorageType.
func isEBSModel(model string) bool {
	return strings.Contains(strings.ToLower(model), "elastic block store")
}

// parseEBSLogPage parses the Amazon EBS stats log page. ok is false unless the
// buffer is long enough AND begins with the EBS magic — guarding against a short
// read or a non-EBS device returning unrelated bytes (which must not be ingested as
// a real, healthy zero reading). Layout: magic u32 @0; the four exceeded-µs counters
// (u64 LE) at offsets 56/64/72/80.
func parseEBSLogPage(buf []byte) (ebsRaw, bool) {
	const minLen = 88
	if len(buf) < minLen {
		return ebsRaw{}, false
	}
	if binary.LittleEndian.Uint32(buf[0:4]) != ebsStatsMagic {
		return ebsRaw{}, false
	}
	return ebsRaw{
		volIOPS:  binary.LittleEndian.Uint64(buf[56:64]),
		volTP:    binary.LittleEndian.Uint64(buf[64:72]),
		instIOPS: binary.LittleEndian.Uint64(buf[72:80]),
		instTP:   binary.LittleEndian.Uint64(buf[80:88]),
	}, true
}

func ebsAnyNonzero(m map[string]ebsRaw) bool {
	for _, r := range m {
		if r.volIOPS > 0 || r.volTP > 0 || r.instIOPS > 0 || r.instTP > 0 {
			return true
		}
	}
	return false
}

// ebsComputeDelta returns, per device, the increase from first to second snapshot.
func ebsComputeDelta(first, second map[string]ebsRaw) map[string]ebsRaw {
	delta := map[string]ebsRaw{}
	for dev, a := range first {
		b := second[dev]
		delta[dev] = ebsRaw{
			volIOPS:  subSat(b.volIOPS, a.volIOPS),
			volTP:    subSat(b.volTP, a.volTP),
			instIOPS: subSat(b.instIOPS, a.instIOPS),
			instTP:   subSat(b.instTP, a.instTP),
		}
	}
	return delta
}

func ebsAssemble(totals, delta map[string]ebsRaw) []models.EBSStats {
	if len(totals) == 0 {
		return nil
	}
	out := make([]models.EBSStats, 0, len(totals))
	for dev, r := range totals {
		s := models.EBSStats{
			Device:                 dev,
			VolumeIOPSExceededUs:   r.volIOPS,
			VolumeTPExceededUs:     r.volTP,
			InstanceIOPSExceededUs: r.instIOPS,
			InstanceTPExceededUs:   r.instTP,
		}
		if d, ok := delta[dev]; ok {
			s.ActiveVolumeIOPSUs = d.volIOPS
			s.ActiveVolumeTPUs = d.volTP
			s.ActiveInstanceIOPSUs = d.instIOPS
			s.ActiveInstanceTPUs = d.instTP
		}
		out = append(out, s)
	}
	sortEBS(out)
	return out
}

func sortEBS(s []models.EBSStats) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].Device < s[j-1].Device; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// subSat returns a-b, saturating at 0 (counters only ever increase, but a NIC reset
// or a re-attached volume could reset them mid-window — never report a negative).
func subSat(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// ---------- IMDS posture ----------

// awsInstanceType returns the instance type from IMDS ("" on any error).
func awsInstanceType(ctx context.Context) string {
	client := &http.Client{Timeout: 2 * time.Second}
	token, err := awsIMDSToken(ctx, client)
	if err != nil {
		return ""
	}
	t, _ := imdsGet(ctx, "http://169.254.169.254/latest/meta-data/instance-type",
		map[string]string{"X-aws-ec2-metadata-token": token})
	return t
}

// awsIMDSv1Open probes whether IMDSv1 (token-less) is still accepted. A token-less
// GET that returns 200 means HttpTokens=optional — the SSRF-reachable posture behind
// the Capital One class of breach; 401 means IMDSv2 is required (good). checked is
// false when IMDS itself was unreachable, so we never imply a posture we couldn't read.
func awsIMDSv1Open(ctx context.Context) (checked, open bool) {
	return probeIMDSOpen(ctx, "aws-imdsv1-probe", "http://169.254.169.254/latest/meta-data/instance-id")
}

// awsRebalance probes the EC2 rebalance-recommendation endpoint (200 = AWS signals
// elevated interruption risk for this spot instance; 404 = none). checked is false
// on any IMDS error so a missed probe never reads as "no recommendation".
func awsRebalance(ctx context.Context) (checked, recommended bool) {
	client := &http.Client{Timeout: 2 * time.Second}
	token, err := awsIMDSToken(ctx, client)
	if err != nil {
		return false, false
	}
	data, err := curSource().Cached("aws-rebalance-probe", func() ([]byte, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet,
			"http://169.254.169.254/latest/meta-data/events/recommendations/rebalance", nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("X-aws-ec2-metadata-token", token)
		resp, e := client.Do(req)
		if e != nil {
			return nil, e
		}
		defer resp.Body.Close() //nolint:errcheck
		if resp.StatusCode == http.StatusOK {
			return []byte("yes"), nil
		}
		return []byte("no"), nil
	})
	if err != nil {
		return false, false
	}
	return true, string(data) == "yes"
}

// ---------- Amazon Time Sync ----------

// amazonTimeSyncConfigured reports whether the NTP client is pointed at the Amazon
// Time Sync Service — the link-local 169.254.169.123 server or the local PHC refclock
// (/dev/ptp). checked is false when no chrony/timesyncd config was found to read, so
// we never claim a verdict on a host whose time config we couldn't see.
func amazonTimeSyncConfigured() (checked, uses bool) {
	files := []string{
		"/etc/chrony.conf",
		"/etc/chrony/chrony.conf",
		"/etc/systemd/timesyncd.conf",
	}
	globs := []string{
		"/etc/chrony/conf.d/*.conf",
		"/etc/chrony/sources.d/*.sources",
		"/etc/chrony.d/*.conf",       // AL2023 / RHEL drop-in layout
		"/etc/chrony.d/*.sources",    // AL2023 / RHEL source files
		"/run/chrony.d/*.sources",    // AL2023 DHCP-supplied Amazon Time Sync server
		"/run/chrony-dhcp/*.sources", // Debian/Ubuntu DHCP-supplied source files
		"/etc/systemd/timesyncd.conf.d/*.conf",
	}
	// chrony.conf can delegate to arbitrary `sourcedir` directories. AL2023 ships
	// `sourcedir /run/chrony.d`, where the DHCP client drops the Amazon Time Sync
	// server (169.254.169.123) at runtime — it never appears under /etc. Honour any
	// sourcedir we find so we read where the real source actually lives, otherwise we
	// false-report "not pointed at Amazon Time Sync" on the default EC2 distro.
	for _, f := range files {
		for _, line := range strings.Split(readFileTrimmedLocal(f), "\n") {
			if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "sourcedir" {
				globs = append(globs, fields[1]+"/*.sources")
			}
		}
	}
	for _, pat := range globs {
		if matches, err := curSource().Glob(pat); err == nil {
			files = append(files, matches...)
		}
	}
	for _, f := range files {
		body := readFileTrimmedLocal(f)
		if body == "" {
			continue
		}
		checked = true
		low := strings.ToLower(body)
		if strings.Contains(low, "169.254.169.123") || strings.Contains(low, "/dev/ptp") || strings.Contains(low, "refclock phc") {
			return true, true
		}
	}
	return checked, false
}

// ---------- SSM agent ----------

// ssmState reports whether the AWS Systems Manager agent is installed and running.
// Installed-but-not-running is the actionable case (SSM-based management is silently
// broken); not-installed is silent (plenty of instances don't use SSM).
func ssmState(ctx context.Context) (installed, running bool) {
	if _, err := lookPath(awsSvcSSMAgent); err == nil {
		installed = true
	}
	for _, p := range []string{
		"/usr/bin/amazon-ssm-agent",
		"/snap/amazon-ssm-agent/current/amazon-ssm-agent",
		"/etc/amazon/ssm",
	} {
		if fileExists(p) {
			installed = true
			break
		}
	}
	if !installed {
		return false, false
	}
	if r, ok := procCommRunning(awsSvcSSMAgent); ok && r {
		return true, true
	}
	for _, unit := range []string{awsSvcSSMAgent, "snap.amazon-ssm-agent.amazon-ssm-agent"} {
		if out, err := runCmd(ctx, "systemctl", "is-active", unit); err == nil &&
			strings.TrimSpace(out) == "active" {
			return true, true
		}
	}
	return true, false
}
