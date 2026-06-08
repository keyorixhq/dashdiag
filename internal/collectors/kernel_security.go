package collectors

import (
	"bufio"
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type KernelSecurityCollector struct{}

func NewKernelSecurityCollector() *KernelSecurityCollector { return &KernelSecurityCollector{} }

func (c *KernelSecurityCollector) Name() string           { return "KernelSec" }
func (c *KernelSecurityCollector) Timeout() time.Duration { return 5 * time.Second }

// parseSELinuxMode normalises getenforce output to lowercase.
func parseSELinuxMode(out string) string {
	return strings.ToLower(strings.TrimSpace(out))
}

func collectSELinux(ctx context.Context) (present bool, mode string, denials int) {
	out, err := localeSafeCmd(ctx, "getenforce").Output()
	if err != nil {
		return false, "", 0
	}
	mode = parseSELinuxMode(string(out))
	present = true
	if mode != "enforcing" {
		return present, mode, 0
	}

	// Prefer reading /var/log/audit/audit.log directly — when auditd is running
	// it intercepts AVC messages at the audit socket, so they never reach journald.
	// Falling back to journald handles the rare case where auditd is absent.
	if n, ok := countAVCsFromAuditLog(1 * time.Hour); ok {
		return present, mode, n
	}

	// Fallback: journald (works only when auditd is NOT running)
	jout, err := localeSafeCmd(ctx, "journalctl",
		"--since=1 hour ago", "--no-pager", "-q").Output()
	if err != nil {
		return present, mode, 0
	}
	denials = strings.Count(string(jout), "avc:  denied")
	return present, mode, denials
}

// ExtractAVCProcesses parses AVC sample lines and returns unique process names
// from the comm= field. Used to suggest targeted boolean searches.
// Example: type=AVC ... comm="httpd" ... → ["httpd"]
func ExtractAVCProcesses(samples []string) []string {
	seen := map[string]bool{}
	var procs []string
	for _, line := range samples {
		idx := strings.Index(line, `comm="`)
		if idx < 0 {
			continue
		}
		rest := line[idx+6:]
		end := strings.IndexByte(rest, '"')
		if end <= 0 {
			continue
		}
		proc := rest[:end]
		if !seen[proc] {
			seen[proc] = true
			procs = append(procs, proc)
		}
	}
	return procs
}

// countAVCsFromAuditLog reads /var/log/audit/audit.log and counts type=AVC
// entries whose Unix timestamp falls within the last window duration.
// Returns (count, true) on success, (0, false) if the file is unreadable.
// When the direct read fails (non-root), falls back to ausearch if available.
func countAVCsFromAuditLog(window time.Duration) (int, bool) {
	f, err := os.Open("/var/log/audit/audit.log") // #nosec G304
	if err != nil {
		// Fallback: try ausearch which uses the auditd socket (works non-root)
		return countAVCsViaAusearch(window)
	}
	defer f.Close() //nolint:errcheck

	cutoff := time.Now().Add(-window)
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "type=AVC") {
			continue
		}
		// Parse Unix timestamp from: msg=audit(1715000000.000:1)
		idx := strings.Index(line, "msg=audit(")
		if idx < 0 {
			continue
		}
		rest := line[idx+10:]
		dotIdx := strings.IndexByte(rest, '.')
		if dotIdx <= 0 {
			continue
		}
		sec, err := strconv.ParseInt(rest[:dotIdx], 10, 64)
		if err != nil {
			continue
		}
		if time.Unix(sec, 0).After(cutoff) {
			count++
		}
	}
	return count, true
}

func apparmorEnabled() bool {
	data, err := os.ReadFile("/sys/module/apparmor/parameters/enabled")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "Y"
}

// apparmorMode returns the AppArmor enforcement mode by inspecting the
// loaded profiles list. Distinguishes three outcomes:
//   - "enforce" / "complain" / "disabled": confirmed mode
//   - "unknown": cannot determine mode (typically EACCES because
//     /sys/kernel/security/apparmor/profiles is root-readable only).
//
// The EACCES distinction matters: on Ubuntu and most Debian-family
// systems the profiles file is mode 0440 root:root. As non-root, the
// previous behaviour was to silently report "disabled" — a wrong
// system-fact claim. Reporting "unknown" lets the analysis layer
// surface the privilege limitation honestly instead of producing a
// false "no kernel security module enforcing" verdict.
func apparmorMode() string {
	return apparmorModeFromPath("/sys/kernel/security/apparmor/profiles")
}

func apparmorModeFromPath(path string) string {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		if os.IsPermission(err) {
			return "unknown"
		}
		return "disabled"
	}
	return parseApparmorProfiles(string(data))
}

// parseApparmorProfiles returns the dominant mode from the profiles list.
func parseApparmorProfiles(data string) string {
	for _, line := range strings.Split(data, "\n") {
		if strings.HasSuffix(line, "(enforce)") {
			return "enforce"
		}
		if strings.HasSuffix(line, "(complain)") {
			return "complain"
		}
	}
	return "disabled"
}

// apparmorDetail returns profile counts by mode from the profiles list.
// Path is /sys/kernel/security/apparmor/profiles — requires root.
func apparmorDetail() (total, enforce, complain int) {
	data, err := os.ReadFile("/sys/kernel/security/apparmor/profiles") // #nosec G304
	if err != nil {
		return 0, 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		total++
		switch {
		case strings.HasSuffix(line, "(enforce)"):
			enforce++
		case strings.HasSuffix(line, "(complain)"):
			complain++
		}
	}
	return total, enforce, complain
}

// countAppArmorDenials counts AppArmor DENIED entries in the audit log
// within the last hour. Returns -1 when the audit log is unreadable.
func countAppArmorDenials(window time.Duration) int {
	f, err := os.Open("/var/log/audit/audit.log") // #nosec G304
	if err != nil {
		// Try dmesg fallback — kernel logs AppArmor denials there too
		return countAppArmorDenialsDmesg(window)
	}
	defer f.Close() //nolint:errcheck

	cutoff := time.Now().Add(-window)
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "apparmor") && !strings.Contains(line, "APPARMOR") {
			continue
		}
		if !strings.Contains(line, "DENIED") && !strings.Contains(line, "denied") {
			continue
		}
		// Parse timestamp from msg=audit(TS.ms:n)
		idx := strings.Index(line, "msg=audit(")
		if idx < 0 {
			count++ // count even if no timestamp
			continue
		}
		rest := line[idx+10:]
		dotIdx := strings.IndexByte(rest, '.')
		if dotIdx <= 0 {
			count++
			continue
		}
		sec, err := strconv.ParseInt(rest[:dotIdx], 10, 64)
		if err != nil || time.Unix(sec, 0).After(cutoff) {
			count++
		}
	}
	return count
}

// countAppArmorDenialsDmesg reads recent kernel messages for AppArmor denials.
func countAppArmorDenialsDmesg(window time.Duration) int {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := runCmd(ctx, "dmesg", "--since",
		time.Now().Add(-window).Format("2006-01-02T15:04:05"))
	if err != nil {
		// dmesg --since may not be supported on all kernels
		out, err = runCmd(ctx, "dmesg")
		if err != nil {
			return -1
		}
	}
	count := 0
	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "apparmor") && strings.Contains(lower, "denied") {
			count++
		}
	}
	return count
}

func (c *KernelSecurityCollector) Collect(ctx context.Context) (interface{}, error) {
	if runtime.GOOS == "darwin" {
		return &models.KernelSecurityInfo{}, nil
	}

	sePresent, seMode, seDenials := collectSELinux(ctx)
	var seAVCSamples []string
	if sePresent && seDenials > 0 {
		seAVCSamples = collectAVCSamples(3)
	}
	aaPresent := apparmorEnabled()
	aaMode := ""
	aaTotal, aaEnforce, aaComplain := 0, 0, 0
	aaDenials := 0
	if aaPresent {
		aaMode = apparmorMode()
		aaTotal, aaEnforce, aaComplain = apparmorDetail()
		aaDenials = countAppArmorDenials(1 * time.Hour)
	}

	// SELinux policy type validation — the Red Hat boot failure case.
	// SELINUXTYPE= in /etc/selinux/config must name a policy whose package is installed
	// and whose directory /etc/selinux/<type>/ exists. When this is wrong, dbus-daemon
	// cannot load its contexts file and cascades to all dependent services at boot.
	seType, seTypeValid, sePolicyDirOK, sePkgOK, seRelabel := validateSELinuxPolicyType()

	return &models.KernelSecurityInfo{
		Available:             true,
		SELinuxPresent:        sePresent,
		SELinuxMode:           seMode,
		SELinuxDenials:        seDenials,
		SELinuxAVCSamples:     seAVCSamples,
		SELinuxType:           seType,
		SELinuxTypeValid:      seTypeValid,
		SELinuxPolicyDirOK:    sePolicyDirOK,
		SELinuxPolicyPkgOK:    sePkgOK,
		SELinuxRelabelPending: seRelabel,
		AppArmorPresent:       aaPresent,
		AppArmorMode:          aaMode,
		AppArmorProfiles:      aaTotal,
		AppArmorEnforce:       aaEnforce,
		AppArmorComplain:      aaComplain,
		AppArmorDenials:       aaDenials,
	}, nil
}

// validateSELinuxPolicyType reads /etc/selinux/config and validates that SELINUXTYPE=
// references an installed, available policy. Returns (type, typeValid, dirOK, pkgOK, relabelPending).
// All return values are zero/false when /etc/selinux/config does not exist (SELinux absent).
func validateSELinuxPolicyType() (seType string, typeValid, dirOK, pkgOK, relabelPending bool) {
	data, err := os.ReadFile("/etc/selinux/config")
	if err != nil {
		return "", false, false, false, false
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "SELINUXTYPE=") {
			seType = strings.TrimPrefix(line, "SELINUXTYPE=")
			seType = strings.TrimSpace(seType)
			break
		}
	}

	if seType == "" {
		return "", false, false, false, false
	}

	// Valid policy types per the SELinux documentation.
	validTypes := map[string]bool{"targeted": true, "minimum": true, "mls": true}
	typeValid = validTypes[seType]

	// Policy directory must exist under /etc/selinux/<type>/
	policyDir := "/etc/selinux/" + seType
	if _, statErr := os.Stat(policyDir); statErr == nil { //nolint:gosec // policyDir built from seType validated against fixed allowlist above
		dirOK = true
	}

	// Policy package selinux-policy-<type> must be installed.
	// Try rpm first (RHEL/CentOS/Fedora), then dpkg (Debian/Ubuntu).
	pkgOK = selinuxPolicyPkgInstalled(seType)

	// /.autorelabel: a reboot with relabeling requested but not yet completed.
	if _, statErr := os.Stat("/.autorelabel"); statErr == nil {
		relabelPending = true
	}

	return seType, typeValid, dirOK, pkgOK, relabelPending
}

// selinuxPolicyPkgInstalled returns true when selinux-policy-<policyType>
// is installed according to rpm or dpkg. Returns true (optimistic) when
// neither package manager is available — prevents false positives on systems
// without a traditional package manager.
func selinuxPolicyPkgInstalled(policyType string) bool {
	pkgName := "selinux-policy-" + policyType

	// Try rpm first — RHEL, CentOS, Fedora, openSUSE.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := runCmd(ctx, "rpm", "-q", pkgName)
	if err == nil && !strings.Contains(out, "not installed") {
		return true
	}

	// Try dpkg — Debian, Ubuntu.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	out2, err2 := runCmd(ctx2, "dpkg", "-s", pkgName)
	if err2 == nil && strings.Contains(out2, "Status: install ok installed") {
		return true
	}

	// Neither package manager found the package installed.
	// If neither tool exists at all, return true to avoid false positive.
	_, rpmExists := os.Stat("/usr/bin/rpm")
	_, dpkgExists := os.Stat("/usr/bin/dpkg")
	if rpmExists != nil && dpkgExists != nil {
		return true // no package manager available — can't verify
	}

	return false
}

// collectAVCSamples reads up to n recent AVC denial lines from audit.log.
// These are shown in dsd output so the admin can see exactly what was denied
// and generate a fix with audit2allow without manual grepping.
func collectAVCSamples(n int) []string {
	f, err := os.Open("/var/log/audit/audit.log") // #nosec G304
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck

	cutoff := time.Now().Add(-1 * time.Hour)
	var samples []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "type=AVC") {
			continue
		}
		// Parse timestamp to stay within 1h window
		idx := strings.Index(line, "msg=audit(")
		if idx >= 0 {
			rest := line[idx+10:]
			dotIdx := strings.IndexByte(rest, '.')
			if dotIdx > 0 {
				if sec, err := strconv.ParseInt(rest[:dotIdx], 10, 64); err == nil {
					if !time.Unix(sec, 0).After(cutoff) {
						continue
					}
				}
			}
		}
		samples = append(samples, line)
		if len(samples) >= n {
			break
		}
	}
	return samples
}

// countAVCsViaAusearch uses the ausearch binary as a fallback when
// /var/log/audit/audit.log is not readable (non-root). ausearch
// communicates with auditd via socket and works for unprivileged users.
// Returns (count, false) if ausearch is not installed or fails.
func countAVCsViaAusearch(window time.Duration) (int, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Convert window to seconds for ausearch -ts
	// ausearch supports: recent, today, this-week, or explicit timestamp
	// Use "recent" for last 10 minutes, otherwise compute start time
	var tsArg string
	if window <= 10*time.Minute {
		tsArg = "recent"
	} else {
		start := time.Now().Add(-window)
		tsArg = start.Format("01/02/2006 15:04:05")
	}

	out, err := runCmd(ctx, "ausearch", "-m", "avc", "-ts", tsArg, "--raw")
	if err != nil {
		// ausearch exits 1 when no records found — not an error
		if strings.Contains(out, "<no matches>") || strings.Contains(out, "no matches") {
			return 0, true
		}
		return 0, false // ausearch not available
	}

	count := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "type=AVC") {
			count++
		}
	}
	return count, true
}
