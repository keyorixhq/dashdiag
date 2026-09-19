package cmd_test

// execallowlist_contract_test.go is a HAND-REVIEWED data file, not generated
// from the current source tree — that distinction is the point: it is the
// independently-stated claim of what dsd is allowed to execute, so a fuzzer
// diffing live behavior against it can catch drift instead of validating
// itself. It was built from the 2026-09-19 exec-call-site audit (every
// exec.CommandContext call site in the repo, read directly) and is meant to
// be extended by a human reading a diff, not by tooling.
//
// Every entry names a resolved binary BASENAME (matched via filepath.Base on
// whatever platform.ExecHook recorded — the fully resolved path at almost
// every call site) and a toolRule: the set of argv PREFIXES considered
// read-only for that binary, plus an optional denyAnywhere list. A recorded
// command matches iff (a) its args slice has at least one of the binary's
// prefixes as a literal prefix, AND (b) none of denyAnywhere appears
// anywhere in args. There is no "binary-level only" entry — every rule must
// list at least one prefix (an empty []string{} prefix means "this exact
// call takes no arguments at all"); a rule with zero prefixes fails the
// build (checkAllowlist's own defensive check).
//
// A prefix token of "*" (wildcardToken) matches exactly one arbitrary arg at
// that position — used only for the few real call sites with dynamic content
// BEFORE the end of the matched prefix (a CVE ID between two fixed flags, a
// bare dynamic SELinux boolean name). Trailing args AFTER the end of a
// prefix are already unconstrained (argsHavePrefix only checks a prefix) —
// that's exactly why denyAnywhere exists: for tools whose real call sites
// append a variable amount of trailing content (journalctl's per-unit `-u`
// repeats, dmesg's optional trailing flags), a short/loose prefix alone
// can't rule out a mutating flag slipped in after it, but denyAnywhere does,
// independent of position.
//
// Binaries dsd can execute ONLY via internal/fleet's ssh/scp (never through
// platform.ExecHook — see internal/platform/exechook.go's doc comment) are
// deliberately absent: "ssh" and "scp". FuzzCommandAllowlist never drives the
// `dsd fleet` subcommand, so they should never appear in a trace regardless.
type toolRule struct {
	prefixes     [][]string
	denyAnywhere []string
}

var execAllowlistContract = map[string]toolRule{
	// --- systemd / service state (query only) ---
	"systemctl": {prefixes: [][]string{
		{"show"}, // baseline.DetectLastDeployTime: "show", <svc>, "--property=ActiveEnterTimestamp", "--value"
		{"is-active"},
		{"is-enabled"},
		{"is-system-running"},
		{"--user", "is-system-running"}, // services_deep_linux.go, svcUserFlag
		{"--user", "is-active"},         // services_deep_linux.go
		{"list-units"},
		{"list-timers"},
	}},
	"systemd-analyze": {prefixes: [][]string{
		{"time"},                // systemd.go collectBootTimes
		{"blame", "--no-pager"}, // systemd.go collectBootTimes, services_deep_linux.go
	}},

	// --- process / host introspection (structurally read-only binaries: no destructive verb exists for any of these) ---
	"ps":    {prefixes: [][]string{{"aux"}, {"axo", "pid,ppid,stat,comm"}}}, // "aux" (init/detector.go), "axo ..." (processes.go zombie/hung-parent scan)
	"pgrep": {prefixes: [][]string{{"-x", "sshd"}, {"timed"}}},
	"w":     {prefixes: [][]string{{"-h"}}}, // sessions.go
	"lsof": {prefixes: [][]string{
		{"-iTCP", "-sTCP:LISTEN", "-n", "-P"},           // security_darwin.go, listening TCP sockets
		{"-p", wildcardToken, "-a", "-d", "txt", "-Fn"}, // processes.go, dynamic PID
		{"-n", "-P", "-F", "pn"},                        // drilldown/fdlimits.go
	}},
	"du": {prefixes: [][]string{{"-xsh", wildcardToken}, {"-sb", wildcardToken}}}, // dynamic path arg
	"dmesg": {
		prefixes: [][]string{
			{}, // bare `dmesg`, several fallback call sites
			{"--time-format", "iso"},
			{"--since", wildcardToken}, // dynamic timestamp
		},
		// dmesg's real mutating surface is the console-log-level/clear family —
		// none of dsd's own call sites use any of these, and none legitimately
		// ever should (a read-only diagnostic has no business changing what the
		// kernel prints to console or discarding ring-buffer content).
		denyAnywhere: []string{"-c", "-C", "-n", "-D", "-E", "--clear", "--console-off", "--console-on", "--console-level", "--read-clear"},
	},
	"journalctl": {
		prefixes: [][]string{
			{"-u"},                 // per-unit log tail, many call sites (cron/k8s/steamos/drilldown/services_deep)
			{"_COMM=sshd"},         // auth_linux.go
			{"-k"},                 // kernel-ring-buffer tail (oom_linux.go, mte_linux.go)
			{"--since=1 hour ago"}, // kernel_security.go
			{"--user"},             // services_deep_linux.go, svcUserFlag
		},
		// journalctl's real mutating/destructive surface — none of dsd's call
		// sites use any of these, and a prefix as short as {"-u"} alone can't
		// rule one out being appended after it, since real call sites have
		// unbounded per-unit trailing content.
		denyAnywhere: []string{
			"--rotate", "--vacuum-time", "--vacuum-size", "--vacuum-files",
			"--flush", "--sync", "--relinquish-var", "--setup-keys",
		},
	},

	// --- package managers: query / dry-run only ---
	"dpkg":       {prefixes: [][]string{{"--audit"}, {"-s"}, {"-l"}}},
	"dpkg-query": {prefixes: [][]string{{"-W"}}},
	"rpm":        {prefixes: [][]string{{"-qa"}, {"-q"}}},
	"dnf": {prefixes: [][]string{
		{"--version"},
		{"advisory", "list", "--security", "--quiet"},
		{"advisory", "info", "--cve", wildcardToken, "--quiet"},
		{"updateinfo", "list", "security", "--quiet"},
		{"updateinfo", "list", "--security", "--quiet"},
		{"updateinfo", "info", "--cve", wildcardToken, "--quiet"},
		{"updateinfo", "info", "--security", "--quiet"},
		{"repolist", "--enabled", "-q"},
		{"check", "-q"},
		// NOTE: "makecache" is DELIBERATELY absent — packages_linux.go's
		// dnfWarmCache() calls `dnf makecache -q`, which writes to dnf's local
		// metadata cache (and can trigger a real network fetch) — a genuine
		// violation of the read-only/no-collector-network invariants this
		// fuzzer exists to enforce. See
		// docs/findings/2026-09-19-FINDING-dnf-makecache-writes-and-network.md.
		// Left excluded on purpose so this oracle fails closed if that code
		// path is ever exercised by a fuzzed/replayed run on an rpm host.
	}},
	"apt-get": {prefixes: [][]string{{"-s", "upgrade"}, {"--simulate", "upgrade"}, {"--simulate", "dist-upgrade"}}},
	"zypper":  {prefixes: [][]string{{"--version"}, {"list-patches"}, {"search", "--installed-only"}, {"locks"}, {"repos"}}},
	"tdnf": {prefixes: [][]string{
		{"--version"},
		{"repolist"},
		{"-j", "repolist"},
		{"updateinfo", "list"},
		{"updateinfo", "list", "--security"},
		{"-j", "updateinfo", "list", "--security"},
		{"updateinfo", "info", "--security"},
	}},
	"debsecan":   {prefixes: [][]string{{"--cve", wildcardToken, "--format", "detail"}}},
	"arch-audit": {prefixes: [][]string{{"--format", "%n %c %s"}, {"-u"}}},

	// --- storage / RAID / filesystem (read-only query) ---
	"smartctl": {prefixes: [][]string{{"-H"}, {"-A"}, {"--scan-open", "--json=c"}, {"-a"}}},
	"nvme":     {prefixes: [][]string{{"smart-log"}, {"get-log"}}},
	"zpool":    {prefixes: [][]string{{"list"}, {"status"}}},
	"lvs": {prefixes: [][]string{
		{"--version"},
		{"--noheadings", "--nosuffix", "--units", "g", "-o", "lv_name,vg_name,lv_attr,data_percent,metadata_percent,origin,lv_size"},
		{"--noheadings", "--nosuffix", "--units", "g", "-o", "lv_name,vg_name,lv_attr,lv_size,copy_percent"},
	}},
	"vgs":        {prefixes: [][]string{{"--noheadings", "--nosuffix", "--units", "g", "-o", "vg_name,vg_size,vg_free,vg_attr"}}},
	"pvs":        {prefixes: [][]string{{"--noheadings", "-o", "vg_name,pv_attr"}}},
	"btrfs":      {prefixes: [][]string{{"filesystem", "show"}, {"device", "stats"}}},
	"multipath":  {prefixes: [][]string{{"-l"}}},
	"multipathd": {prefixes: [][]string{{"show", "paths"}}},
	"drbdsetup":  {prefixes: [][]string{{"status"}}},
	"ceph":       {prefixes: [][]string{{"health", "detail"}, {"osd", "stat"}}},

	// --- firewall / network (query only) ---
	"nft":           {prefixes: [][]string{{"list", "ruleset"}}},
	"iptables":      {prefixes: [][]string{{"-L"}, {"-nvL"}}},
	"iptables-save": {prefixes: [][]string{{"-t", "nat"}}},
	"firewall-cmd": {prefixes: [][]string{
		{"--state"}, {"--get-default-zone"}, {"--list-services"}, {"--list-ports"},
		{"--get-active-zones"}, {"--query-masquerade"},
	}},
	"ufw": {prefixes: [][]string{{"status"}}},
	"ss":  {prefixes: [][]string{{"-tulpn"}, {"-tlnp"}, {"-tnp", "--no-header"}}},

	// --- SSH effective config (query only) ---
	"sshd": {prefixes: [][]string{{"-T"}}}, // security_linux.go: effective sshd_config dump, root only
	"nmcli": {prefixes: [][]string{
		{"-t", "-f", "ACTIVE,SSID,SIGNAL,RATE,CHAN,BSSID", "dev", "wifi", "list"},
		{"dev", "show"},
	}},
	"networkctl": {prefixes: [][]string{{"list"}}},
	"ping":       {prefixes: [][]string{{"-c", "5", "-i", "0.2", "-W", "1"}}}, // args continue with an optional "-I <srcIP>" then "<host>", both trailing
	"route":      {prefixes: [][]string{{"-n", "get", "default"}}},
	"ip": {prefixes: [][]string{
		{"route", "get", wildcardToken}, // network_quick.go, dynamic destination IP
		{"route", "show", "default"},    // steamos_linux.go
	}},

	// --- SELinux / AppArmor / audit (query only — remediation strings are display-only, never exec'd) ---
	"getenforce": {prefixes: [][]string{{}}},                      // always called bare
	"getsebool":  {prefixes: [][]string{{"-a"}, {wildcardToken}}}, // "-a" (list all), or a single dynamic boolean name
	"semanage":   {prefixes: [][]string{{"port", "-C", "-l"}, {"fcontext", "-C", "-l"}}},
	"auditctl":   {prefixes: [][]string{{"-l"}}},
	"ausearch":   {prefixes: [][]string{{"-ts", "1hour ago", "--raw"}}},
	"aa-status":  {prefixes: [][]string{{"--pretty-json"}, {}}},

	// --- hypervisor / container (read-only) ---
	"virsh": {prefixes: [][]string{
		{"version"}, {"list"}, {"dumpxml"}, {"dominfo"}, {"domblkerror"},
		{"net-list"}, {"net-info"}, {"pool-list"}, {"pool-info"},
	}},
	"pvesh":          {prefixes: [][]string{{"get"}}},
	"pveversion":     {prefixes: [][]string{{"-v"}, {}}},
	"pveperf":        {prefixes: [][]string{{wildcardToken}}}, // single dynamic path arg
	"machinectl":     {prefixes: [][]string{{"list"}}},
	"docker":         {prefixes: [][]string{{"--version"}, {"compose", "version", "--short"}}},
	"docker-compose": {prefixes: [][]string{{"version", "--short"}}}, // docker.go detectComposeStandalone, v1 standalone binary

	// --- k8s (verb is always a hardcoded literal at the call site) ---
	"kubectl":  {prefixes: [][]string{{"get"}, {"logs"}}},
	"k3s":      {prefixes: [][]string{{"kubectl", "get"}, {"kubectl", "logs"}}},
	"k0s":      {prefixes: [][]string{{"kubectl", "get"}, {"kubectl", "logs"}}},
	"microk8s": {prefixes: [][]string{{"kubectl", "get"}, {"kubectl", "logs"}}},

	// --- DB clients: single hardcoded read-only query each ---
	"mongosh":   {prefixes: [][]string{{"--quiet", "--eval", mongoEvalScriptForContract}}},
	"mongo":     {prefixes: [][]string{{"--quiet", "--eval", mongoEvalScriptForContract}}}, // legacy shell fallback, same script
	"mysql":     {prefixes: [][]string{{"-e"}}},
	"psql":      {prefixes: [][]string{{"-c"}}},
	"redis-cli": {prefixes: [][]string{{"INFO"}, {"CONFIG", "GET", "maxclients"}}},

	// --- time / clock ---
	"chronyc":     {prefixes: [][]string{{"tracking"}}},
	"timedatectl": {prefixes: [][]string{{"show"}}},
	"sntp":        {prefixes: [][]string{{"-t"}}},

	// --- misc query tools (structurally read-only: no write/mutating mode exists for any of these) ---
	"ioreg":     {prefixes: [][]string{{"-rn", "AppleSmartBattery"}, {"-rn", "X86PlatformPlugin"}}},
	"dmidecode": {prefixes: [][]string{{"-t", "memory"}, {"-s", "bios-version"}}},
	"nc":        {prefixes: [][]string{{"-z"}}},                                                // port probe only
	"grep":      {prefixes: [][]string{{"-E", "Failed password|Invalid user", wildcardToken}}}, // dynamic log path
	"which":     {prefixes: [][]string{{"sshd"}, {"brew"}}},                                    // auth_linux.go presence check; packages_notlinux.go (darwin)
	"last":      {prefixes: [][]string{{"-x", "-n", "20"}}},                                    // postboot_linux.go
	"nvidia-smi": {prefixes: [][]string{
		{"--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,driver_version,power.limit", "--format=csv,noheader,nounits"},
		{"--query-compute-apps=pid,used_memory,name", "--format=csv,noheader,nounits"},
	}},

	// --- macOS-only collectors (read-only query) ---
	"sysctl": {prefixes: [][]string{
		{"-n", "vm.loadavg"},                          // cpu.go
		{"-n", "kern.maxfiles"},                       // fdlimits.go
		{"-n", "kern.memorystatus_vm_pressure_level"}, // swap.go
	}},
	"diskutil": {prefixes: [][]string{{"list"}, {"info"}}}, // list, or "info <dev>" (dev is a diskutil-discovered name, not fuzz-controlled)
	"networksetup": {prefixes: [][]string{
		{"-getmedia"}, // "-getmedia <iface>"
		{"-listallhardwareports"},
	}},
	"socketfilterfw": {prefixes: [][]string{{"--getglobalstate"}}},         // resolved path: /usr/libexec/ApplicationFirewall/socketfilterfw (security_darwin.go); matched by basename like every other entry
	"launchctl":      {prefixes: [][]string{{"list"}}},                     // launchd_darwin.go
	"iostat":         {prefixes: [][]string{{"-d", "-c", "2", "-w", "1"}}}, // io.go, two-sample disk stats read
	"fdesetup":       {prefixes: [][]string{{"status"}}},                   // security_darwin.go, FileVault status query
	"csrutil":        {prefixes: [][]string{{"status"}}},                   // security_darwin.go, System Integrity Protection status query
	"spctl":          {prefixes: [][]string{{"--status"}}},                 // security_darwin.go, Gatekeeper status query
}

// mongoEvalScriptForContract is a byte-for-byte copy of
// internal/collectors/mongodb_linux.go's unexported mongoEvalScript constant
// (cross-package, can't import it directly — this file is hand-reviewed data
// specifically so it doesn't depend on production code compiling a certain
// way). If that constant's script ever changes, this copy must be updated in
// the same change or FuzzCommandAllowlist will correctly start failing.
const mongoEvalScriptForContract = `var o={};var h=db.hello();o.v=db.version();o.set=h.setName||"";` +
	`var c=db.serverStatus().connections;o.cc=c.current;o.ca=c.available;` +
	`if(o.set){try{var s=rs.status();` +
	`o.hp=s.members.some(function(m){return m.stateStr=="PRIMARY"});` +
	`o.dm=s.members.filter(function(m){return m.health===0}).length;` +
	`o.mn=s.members.length}catch(e){o.re=String(e)}}print(JSON.stringify(o))`

// execAllowlistKnownException documents call sites that DON'T go through
// platform.ResolveTrustedTool and so are recorded with a bare/relative name
// rather than a resolved path — currently just localeSafeCmd's "ping"/"route"
// call sites (internal/collectors/network_quick.go), tracked as KV-PING-ROUTE-
// UNRESOLVED in the known-violations registry (knownviolations_test.go). The
// allowlist entries above for "ping"/"route" already cover their args either
// way; this map exists so the contract file states the gap explicitly rather
// than silently relying on the coincidence that both names also happen to be
// valid resolved-basenames.
var execAllowlistKnownException = map[string]string{
	"ping":  "KV-PING-ROUTE-UNRESOLVED",
	"route": "KV-PING-ROUTE-UNRESOLVED",
}
