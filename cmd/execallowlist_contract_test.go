package cmd_test

// execallowlist_contract_test.go is a HAND-REVIEWED data file, not generated
// from the current source tree — that distinction is the point: it is the
// independently-stated claim of what dsd is allowed to execute, so a fuzzer
// diffing live behavior against it can catch drift instead of validating
// itself. It was built from the 2026-09-19 exec-call-site audit (every
// exec.CommandContext call site in the repo, read directly) and is meant to
// be extended by a human reading a diff, not by tooling.
//
// Each entry names a resolved binary BASENAME (matched via filepath.Base on
// whatever platform.ExecHook recorded — the fully resolved path at almost
// every call site) and the set of argv PREFIXES considered read-only for that
// binary. A recorded command matches the contract iff its args slice has one
// of the binary's allowed prefixes as a literal prefix. An empty prefix ([])
// matches any args (used sparingly, only for binaries dsd invokes exactly one
// documented way).
//
// Binaries dsd can execute ONLY via internal/fleet's ssh/scp (never through
// platform.ExecHook — see internal/platform/exechook.go's doc comment) are
// deliberately absent: "ssh" and "scp". FuzzCommandAllowlist never drives the
// `dsd fleet` subcommand, so they should never appear in a trace regardless.
var execAllowlistContract = map[string][][]string{
	// --- systemd / service state (query only) ---
	"systemctl": {
		{"show"}, // baseline.DetectLastDeployTime: "show", <svc>, "--property=ActiveEnterTimestamp", "--value"
		{"is-active"},
		{"is-enabled"},
		{"is-system-running"},
		{"list-units"},
		{"list-timers"},
	},

	// --- process / host introspection ---
	"ps":         {{"aux"}, {"axo", "pid,ppid,stat,comm"}}, // "aux" (init/detector.go), "axo ..." (processes.go zombie/hung-parent scan)
	"pgrep":      nil,                                      // any args: query-only by construction, no destructive pgrep verb exists
	"lsof":       nil,
	"w":          {{"-h"}},
	"dmesg":      nil,
	"journalctl": nil, // read/filter/--verify only; never --vacuum-*, --rotate, --flush
	"du":         nil, // disk usage query, no writes
	"uptime":     nil,

	// --- package managers: query / dry-run only ---
	"dpkg":       {{"--audit"}, {"-s"}, {"-l"}},
	"dpkg-query": {{"-W"}},
	"rpm":        {{"-qa"}, {"-q"}},
	"dnf":        {{"repolist"}, {"advisory"}},
	"apt-get":    {{"-s", "upgrade"}, {"--simulate", "upgrade"}, {"--simulate", "dist-upgrade"}},
	"zypper":     {{"list-patches"}, {"search", "--installed-only"}, {"locks"}, {"repos"}},
	"tdnf":       {{"repolist"}, {"updateinfo", "list"}},
	"debsecan":   nil,
	"arch-audit": nil,

	// --- storage / RAID / filesystem (read-only query) ---
	"smartctl":   {{"-H"}, {"-A"}, {"--scan-open"}, {"--json=c"}, {"-a"}},
	"nvme":       {{"smart-log"}, {"get-log"}},
	"zpool":      {{"list"}, {"status"}},
	"lvs":        nil,
	"vgs":        nil,
	"pvs":        nil,
	"btrfs":      {{"filesystem", "show"}, {"device", "stats"}},
	"multipath":  {{"-l"}},
	"multipathd": {{"show", "paths"}},
	"drbdsetup":  {{"status"}},
	"ceph":       {{"health", "detail"}, {"osd", "stat"}},

	// --- firewall / network (query only) ---
	"nft":           {{"list", "ruleset"}},
	"iptables":      {{"-L"}, {"-nvL"}},
	"iptables-save": nil,
	"firewall-cmd": {
		{"--state"}, {"--get-default-zone"}, {"--list-services"}, {"--list-ports"},
		{"--get-active-zones"}, {"--query-masquerade"},
	},
	"ufw":        {{"status"}},
	"ss":         nil,
	"nmcli":      nil, // read-only field queries only (-t ...); no `nmcli connection up/down/modify` call site exists
	"networkctl": {{"list"}},
	"ping":       nil, // args are always "-c 5 -i 0.2 -W 1 [-I <ip>] <host>" — icmp echo only, no side effects
	"route":      {{"-n", "get", "default"}},

	// --- SELinux / AppArmor / audit (query only — remediation strings are display-only, never exec'd) ---
	"getenforce": nil,
	"getsebool":  {{"-a"}, nil}, // bare `getsebool <name>` also allowed
	"semanage":   {{"port", "-C", "-l"}, {"fcontext", "-C", "-l"}},
	"auditctl":   {{"-l"}},
	"ausearch":   nil, // always with --raw per the audit; ausearch has no mutating verb
	"aa-status":  nil,

	// --- hypervisor / container (read-only) ---
	"virsh": {
		{"version"}, {"list"}, {"dumpxml"}, {"dominfo"}, {"domblkerror"},
		{"net-list"}, {"net-info"}, {"pool-list"}, {"pool-info"},
	},
	"pvesh":          {{"get"}},
	"pveversion":     nil,
	"pveperf":        nil,
	"machinectl":     {{"list"}},
	"docker":         {{"--version"}, {"compose", "version", "--short"}},
	"docker-compose": {{"version", "--short"}}, // docker.go detectComposeStandalone, v1 standalone binary

	// --- k8s (verb is always a hardcoded literal at the call site) ---
	"kubectl":  {{"get"}, {"logs"}},
	"k3s":      {{"kubectl", "get"}, {"kubectl", "logs"}},
	"k0s":      {{"kubectl", "get"}, {"kubectl", "logs"}},
	"microk8s": {{"kubectl", "get"}, {"kubectl", "logs"}},

	// --- DB clients: single hardcoded read-only query each ---
	"mongosh":   nil, // --eval with a hardcoded read-only script (db.hello(), db.serverStatus(), rs.status())
	"mysql":     {{"-e"}},
	"psql":      {{"-c"}},
	"redis-cli": {{"INFO"}, {"CONFIG", "GET", "maxclients"}},

	// --- time / clock ---
	"chronyc":     {{"tracking"}},
	"timedatectl": {{"show"}},
	"sntp":        {{"-t"}},

	// --- misc query tools ---
	"ioreg":     nil,
	"dmidecode": nil,
	"nc":        {{"-z"}}, // port probe only
	"grep":      nil,      // fixed static log path per call site

	// --- macOS-only collectors (read-only query) ---
	"sysctl": {
		{"-n", "vm.loadavg"},                          // cpu.go
		{"-n", "kern.maxfiles"},                       // fdlimits.go
		{"-n", "kern.memorystatus_vm_pressure_level"}, // swap.go
	},
	"diskutil": {{"list"}, {"info"}}, // list, or "info <dev>" (dev is a diskutil-discovered name, not fuzz-controlled)
	"networksetup": {
		{"-getmedia"}, // "-getmedia <iface>"
		{"-listallhardwareports"},
	},
	"socketfilterfw": {{"--getglobalstate"}},         // resolved path: /usr/libexec/ApplicationFirewall/socketfilterfw (security_darwin.go); matched by basename like every other entry
	"launchctl":      {{"list"}},                     // launchd_darwin.go
	"iostat":         {{"-d", "-c", "2", "-w", "1"}}, // io.go, two-sample disk stats read
	"fdesetup":       {{"status"}},                   // security_darwin.go, FileVault status query
	"csrutil":        {{"status"}},                   // security_darwin.go, System Integrity Protection status query
	"spctl":          {{"--status"}},                 // security_darwin.go, Gatekeeper status query
}

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
