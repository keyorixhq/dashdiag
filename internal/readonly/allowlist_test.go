//go:build linux

package readonly

import "strings"

// This file is the EXEC oracle's data and matcher. It is a faithful in-process
// PORT of cmd/execallowlist_contract_test.go (package cmd_test, not importable
// from here) — the hand-reviewed, not-generated statement of exactly what dsd is
// allowed to execute, from the 2026-09-19 exec-call-site audit. The semantics
// are identical to FuzzCommandAllowlist's checkAllowlist:
//
//   a recorded command matches iff (a) its args have at least one of the binary's
//   prefixes as a literal prefix (wildcardToken "*" matches exactly one arbitrary
//   arg), AND (b) none of denyAnywhere appears anywhere in args.
//
// A mutating invocation (`systemctl stop x`, `dmesg -C`, `dnf install`) is caught
// precisely because it matches no read-only prefix (or trips denyAnywhere) — that
// is the "any allowed command invoked with a mutating argument fails the test"
// oracle, with the contract's zero-false-positive precision rather than a blunt
// universal denylist (which would wrongly flag the legitimate read-only
// `apt-get -s upgrade` / `dnf ... updateinfo list` call sites).
//
// If the upstream contract ever changes, this port must change with it; the two
// are kept honest by a human reading a diff, exactly as the upstream file's own
// header requires. Keeping it a separate copy (vs. reaching into cmd_test) is
// forced by Go test-package scoping and is the same tradeoff the contract file
// already makes for mongoEvalScript.

const wildcardToken = "*"

type toolRule struct {
	prefixes     [][]string
	denyAnywhere []string
}

// readOnlyBinaries is the membership set used by the PATH-shim oracle and
// buildShimDir, derived from execAllowlistContract's keys so the two can never
// drift from each other.
var readOnlyBinaries = func() map[string]bool {
	m := make(map[string]bool, len(execAllowlistContract))
	for k := range execAllowlistContract {
		m[k] = true
	}
	return m
}()

var execAllowlistContract = map[string]toolRule{
	"systemctl": {prefixes: [][]string{
		{"show"}, {"is-active"}, {"is-enabled"}, {"is-system-running"},
		{"--user", "is-system-running"}, {"--user", "is-active"},
		{"list-units"}, {"list-timers"},
		// RO1 finding: `systemctl --user list-units --failed ...`
		// (services_deep_linux.go) is a read-only user-scope unit list missing from
		// the upstream contract (which has --user is-active/is-system-running but
		// not --user list-units).
		{"--user", "list-units"},
	}},
	"systemd-analyze": {prefixes: [][]string{{"time"}, {"blame", "--no-pager"}}},

	"ps":    {prefixes: [][]string{{"aux"}, {"axo", "pid,ppid,stat,comm"}, {"-axro", "pid,pmem,rss,comm"}, {"-axro", "pid,pcpu,comm"}}},
	"pgrep": {prefixes: [][]string{{"-x", "sshd"}, {"timed"}}},
	"w":     {prefixes: [][]string{{"-h"}}},
	"lsof": {prefixes: [][]string{
		{"-iTCP", "-sTCP:LISTEN", "-n", "-P"},
		{"-p", wildcardToken, "-a", "-d", "txt", "-Fn"},
		{"-n", "-P", "-F", "pn"},
	}},
	"du": {prefixes: [][]string{{"-xsh", wildcardToken}, {"-sb", wildcardToken}}},
	"dmesg": {
		prefixes:     [][]string{{}, {"--time-format", "iso"}, {"--since", wildcardToken}},
		denyAnywhere: []string{"-c", "-C", "-n", "-D", "-E", "--clear", "--console-off", "--console-on", "--console-level", "--read-clear"},
	},
	"journalctl": {
		prefixes: [][]string{
			{"-u"}, {"_COMM=sshd"}, {"-k"}, {"--since=1 hour ago"}, {"--user"},
			{"-p", "err"}, {"-p", "warning"}, {"--since=24 hours ago"}, {"-t", "kernel"},
			// RO1 finding: `journalctl --verify --file=<archived *.journal~>` is a
			// real, read-only dsd call site (logs_linux.go:609,
			// services_deep_linux.go) that is MISSING from the upstream
			// cmd_test.execAllowlistContract. --verify checks journal integrity and
			// modifies nothing. It only ever fires on a host that has archived
			// journals present during the run, which is why the upstream audit and
			// FuzzCommandAllowlist (usually run where none exist) never recorded it.
			// Added here as a genuinely read-only verb; reported as an upstream
			// contract gap, see .scratch/ro1-REPORT.md.
			{"--verify"},
			// RO1 finding: `journalctl --list-boots --no-pager -q` (postboot_linux.go:90)
			// — read-only boot enumeration, also missing from the upstream contract.
			{"--list-boots"},
		},
		denyAnywhere: []string{"--rotate", "--vacuum-time", "--vacuum-size", "--vacuum-files", "--flush", "--sync", "--relinquish-var", "--setup-keys"},
	},

	"dpkg":       {prefixes: [][]string{{"--audit"}, {"-s"}, {"-l"}}},
	"dpkg-query": {prefixes: [][]string{{"-W"}}},
	// RO1 finding: `rpm --verify <canary>` (packages_linux.go:1044) is a real,
	// read-only dsd call site (verifies installed files against the RPM DB, no
	// modification) also MISSING from the upstream contract. Added here; reported
	// as an upstream contract gap. Only fires on rpm-based hosts.
	"rpm": {prefixes: [][]string{{"-qa"}, {"-q"}, {"--verify"}}},
	"dnf": {prefixes: [][]string{
		{"--version"},
		{"--cacheonly", "advisory", "list", "--security", "--quiet"},
		{"--cacheonly", "advisory", "info", "--cve", wildcardToken, "--quiet"},
		{"--cacheonly", "updateinfo", "list", "security", "--quiet"},
		{"--cacheonly", "updateinfo", "info", "--cve", wildcardToken, "--quiet"},
		{"--cacheonly", "updateinfo", "info", "--security", "--quiet"},
		{"--cacheonly", "repolist", "--enabled", "-q"},
		{"--cacheonly", "check", "--quiet"},
	}},
	// RO1 finding: `apt-get --version` (packages_linux.go:145, PM-detection probe)
	// is a read-only call site missing from the upstream contract. NOTE: the sibling
	// call site `apt-get check` (packages_linux.go:1093) is deliberately NOT added —
	// `apt-get check` can rewrite /var/cache/apt/pkgcache.bin, so it is not a pure
	// read-only command; it is flagged as a CANDIDATE in the report rather than
	// endorsed here.
	"apt-get": {prefixes: [][]string{{"-s", "upgrade"}, {"--simulate", "upgrade"}, {"--simulate", "dist-upgrade"}, {"--version"}}},
	// RO1 finding: `zypper needs-rebooting` (maintenance_linux.go:258, read-only
	// reboot check) and `zypper --non-interactive --no-color list-patches ...`
	// (cve_linux.go:609 / packages_linux.go:724, read-only patch list with leading
	// global flags the bare {"list-patches"} prefix can't match) are both missing
	// from the upstream contract.
	"zypper": {prefixes: [][]string{{"--version"}, {"list-patches"}, {"--non-interactive", "--no-color", "list-patches"}, {"needs-rebooting"}, {"search", "--installed-only"}, {"locks"}, {"repos"}}},
	"tdnf": {prefixes: [][]string{
		{"--version"}, {"repolist"}, {"-j", "repolist"}, {"updateinfo", "list"},
		{"updateinfo", "list", "--security"}, {"-j", "updateinfo", "list", "--security"}, {"updateinfo", "info", "--security"},
	}},
	"debsecan":               {prefixes: [][]string{{"--cve", wildcardToken, "--format", "detail"}}},
	"arch-audit":             {prefixes: [][]string{{"--format", "%n %c %s"}, {"-u"}}},
	"systemd-detect-virt":    {prefixes: [][]string{{"-v"}}},
	"pro":                    {prefixes: [][]string{{"status", "--format", "json"}, {"security-status", "--format", "json"}}},
	"update-crypto-policies": {prefixes: [][]string{{"--show"}}},

	"cloud-init": {prefixes: [][]string{{"status", "--format=json"}, {"status"}}},

	"smartctl":   {prefixes: [][]string{{"-H"}, {"-A"}, {"--scan-open", "--json=c"}, {"-a"}}},
	"nvme":       {prefixes: [][]string{{"smart-log"}, {"get-log"}}},
	"ethtool":    {prefixes: [][]string{{"-S"}}},
	"zpool":      {prefixes: [][]string{{"list"}, {"status"}}},
	"lvs":        {prefixes: [][]string{{"--version"}, {"--noheadings", "--nosuffix", "--units", "g", "-o", "lv_name,vg_name,lv_attr,data_percent,metadata_percent,origin,lv_size"}, {"--noheadings", "--nosuffix", "--units", "g", "-o", "lv_name,vg_name,lv_attr,lv_size,copy_percent"}}},
	"vgs":        {prefixes: [][]string{{"--noheadings", "--nosuffix", "--units", "g", "-o", "vg_name,vg_size,vg_free,vg_attr"}}},
	"pvs":        {prefixes: [][]string{{"--noheadings", "-o", "vg_name,pv_attr"}}},
	"btrfs":      {prefixes: [][]string{{"filesystem", "show"}, {"device", "stats"}}},
	"multipath":  {prefixes: [][]string{{"-l"}}},
	"multipathd": {prefixes: [][]string{{"show", "paths"}}},
	"drbdsetup":  {prefixes: [][]string{{"status"}}},
	"ceph":       {prefixes: [][]string{{"health", "detail"}, {"osd", "stat"}}},

	"nft":           {prefixes: [][]string{{"list", "ruleset"}}},
	"iptables":      {prefixes: [][]string{{"-L"}, {"-nvL"}}},
	"iptables-save": {prefixes: [][]string{{"-t", "nat"}}},
	"firewall-cmd":  {prefixes: [][]string{{"--state"}, {"--get-default-zone"}, {"--list-services"}, {"--list-ports"}, {"--get-active-zones"}, {"--query-masquerade"}}},
	"ufw":           {prefixes: [][]string{{"status"}}},
	"ss":            {prefixes: [][]string{{"-tulpn"}, {"-tlnp"}, {"-tnp", "--no-header"}}},

	"sshd":       {prefixes: [][]string{{"-T"}}},
	"nmcli":      {prefixes: [][]string{{"-t", "-f", "ACTIVE,SSID,SIGNAL,RATE,CHAN,BSSID", "dev", "wifi", "list"}, {"dev", "show"}}},
	"networkctl": {prefixes: [][]string{{"list"}}},
	"ping":       {prefixes: [][]string{{"-c", "5", "-i", "0.2", "-W", "1"}}},
	"route":      {prefixes: [][]string{{"-n", "get", "default"}}},
	"ip":         {prefixes: [][]string{{"route", "get", wildcardToken}, {"route", "show", "default"}}},

	"getenforce": {prefixes: [][]string{{}}},
	"getsebool":  {prefixes: [][]string{{"-a"}, {wildcardToken}}},
	"semanage":   {prefixes: [][]string{{"port", "-C", "-l"}, {"fcontext", "-C", "-l"}}},
	"auditctl":   {prefixes: [][]string{{"-l"}}},
	"ausearch":   {prefixes: [][]string{{"-ts", "1hour ago", "--raw"}}},
	"aa-status":  {prefixes: [][]string{{"--pretty-json"}, {}}},
	"faillock":   {prefixes: [][]string{{"--user", wildcardToken}}},

	"virsh":          {prefixes: [][]string{{"version"}, {"list"}, {"dumpxml"}, {"dominfo"}, {"domblkerror"}, {"net-list"}, {"net-info"}, {"pool-list"}, {"pool-info"}}},
	"pvesh":          {prefixes: [][]string{{"get"}}},
	"pveversion":     {prefixes: [][]string{{"-v"}, {}}},
	"pveperf":        {prefixes: [][]string{{wildcardToken}}},
	"machinectl":     {prefixes: [][]string{{"list"}}},
	"docker":         {prefixes: [][]string{{"--version"}, {"compose", "version", "--short"}}},
	"docker-compose": {prefixes: [][]string{{"version", "--short"}}},

	"kubectl":  {prefixes: [][]string{{"get"}, {"logs"}}},
	"k3s":      {prefixes: [][]string{{"kubectl", "get"}, {"kubectl", "logs"}}},
	"k0s":      {prefixes: [][]string{{"kubectl", "get"}, {"kubectl", "logs"}}},
	"microk8s": {prefixes: [][]string{{"kubectl", "get"}, {"kubectl", "logs"}}},

	"mongosh":   {prefixes: [][]string{{"--quiet", "--eval", mongoEvalScriptForContract}}},
	"mongo":     {prefixes: [][]string{{"--quiet", "--eval", mongoEvalScriptForContract}}},
	"mysql":     {prefixes: [][]string{{"-e"}}},
	"psql":      {prefixes: [][]string{{"-c"}}},
	"redis-cli": {prefixes: [][]string{{"INFO"}, {"CONFIG", "GET", "maxclients"}}},

	"chronyc":     {prefixes: [][]string{{"tracking"}}},
	"timedatectl": {prefixes: [][]string{{"show"}}},
	"sntp":        {prefixes: [][]string{{"-t"}}},

	"ioreg":      {prefixes: [][]string{{"-rn", "AppleSmartBattery"}, {"-rn", "X86PlatformPlugin"}}},
	"dmidecode":  {prefixes: [][]string{{"-t", "memory"}, {"-s", "bios-version"}}},
	"nc":         {prefixes: [][]string{{"-z"}}},
	"grep":       {prefixes: [][]string{{"-E", "Failed password|Invalid user", wildcardToken}}},
	"which":      {prefixes: [][]string{{"sshd"}, {"brew"}}},
	"last":       {prefixes: [][]string{{"-x", "-n", "20"}}},
	"nvidia-smi": {prefixes: [][]string{{"--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,driver_version,power.limit", "--format=csv,noheader,nounits"}, {"--query-compute-apps=pid,used_memory,name", "--format=csv,noheader,nounits"}}},

	// macOS-only entries (never reached under GOOS=linux; kept so the port is a
	// 1:1 mirror the drift-check can validate).
	"sysctl":         {prefixes: [][]string{{"-n", "vm.loadavg"}, {"-n", "kern.maxfiles"}, {"-n", "kern.memorystatus_vm_pressure_level"}}},
	"diskutil":       {prefixes: [][]string{{"list"}, {"info"}}},
	"networksetup":   {prefixes: [][]string{{"-getmedia"}, {"-listallhardwareports"}}},
	"socketfilterfw": {prefixes: [][]string{{"--getglobalstate"}}},
	"launchctl":      {prefixes: [][]string{{"list"}}},
	"iostat":         {prefixes: [][]string{{"-d", "-c", "2", "-w", "1"}}},
	"fdesetup":       {prefixes: [][]string{{"status"}}},
	"csrutil":        {prefixes: [][]string{{"status"}}},
	"spctl":          {prefixes: [][]string{{"--status"}}},
}

// mongoEvalScriptForContract is a byte-for-byte copy of
// internal/collectors/mongodb_linux.go's unexported mongoEvalScript (same copy
// cmd/execallowlist_contract_test.go keeps, for the same cross-package reason).
const mongoEvalScriptForContract = `var o={};var h=db.hello();o.v=db.version();o.set=h.setName||"";` +
	`var c=db.serverStatus().connections;o.cc=c.current;o.ca=c.available;` +
	`if(o.set){try{var s=rs.status();` +
	`o.hp=s.members.some(function(m){return m.stateStr=="PRIMARY"});` +
	`o.dm=s.members.filter(function(m){return m.health===0}).length;` +
	`o.mn=s.members.length}catch(e){o.re=String(e)}}print(JSON.stringify(o))`

func argsHavePrefix(args, prefix []string) bool {
	if len(args) < len(prefix) {
		return false
	}
	for i, p := range prefix {
		if p == wildcardToken {
			continue
		}
		if args[i] != p {
			return false
		}
	}
	return true
}

func argsContainAny(args, denyAnywhere []string) string {
	for _, a := range args {
		for _, d := range denyAnywhere {
			if strings.HasPrefix(a, d) {
				return a
			}
		}
	}
	return ""
}
