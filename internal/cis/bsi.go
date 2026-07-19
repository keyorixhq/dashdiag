package cis

import "github.com/keyorixhq/dashdiag/internal/models"

// BSIRequirement describes one Anforderung (requirement) from the BSI
// IT-Grundschutz Kompendium (Edition 2023).
type BSIRequirement struct {
	ID      string // e.g. "SYS.1.3.A4"
	Title   string // German short title
	Level   string // "B" = Basis, "S" = Standard, "H" = Erhöhter Schutzbedarf
	English string // English translation of the title
}

// BSIBaustein describes one building block (Baustein) from the Kompendium.
type BSIBaustein struct {
	ID           string
	Title        string
	English      string
	Requirements []BSIRequirement
}

// BSIBausteine lists the building blocks included in the dsd cis --bsi report.
// Only the three blocks with verifiable OS-level technical controls are included:
// SYS.1.3 (Linux server), SYS.1.1 (general server), and the OPS.1.1 operations layer.
var BSIBausteine = []BSIBaustein{
	{
		ID:      "SYS.1.3",
		Title:   "Server unter Linux und Unix",
		English: "Servers under Linux and Unix",
		Requirements: []BSIRequirement{
			{
				ID:      "SYS.1.3.A2",
				Title:   "Sorgfältige Vergabe von IDs",
				Level:   "B",
				English: "Careful assignment of user and group IDs",
			},
			{
				ID:      "SYS.1.3.A3",
				Title:   "Kein automatisches Einbinden von Wechsellaufwerken",
				Level:   "B",
				English: "No automatic mounting of removable media",
			},
			{
				ID:      "SYS.1.3.A4",
				Title:   "Schutz vor Ausnutzung von Schwachstellen",
				Level:   "B",
				English: "Protection against exploitation of vulnerabilities (ASLR, NX, kernel hardening)",
			},
			{
				ID:      "SYS.1.3.A5",
				Title:   "Sichere Installation von Software-Paketen",
				Level:   "B",
				English: "Secure installation of software packages (signed repos, integrity checking)",
			},
			{
				ID:      "SYS.1.3.A6",
				Title:   "Verwaltung von Benutzern und Gruppen",
				Level:   "S",
				English: "Management of users and groups (tools, file permissions)",
			},
			{
				ID:      "SYS.1.3.A8",
				Title:   "Verschlüsselter Zugriff über Secure Shell",
				Level:   "S",
				English: "Encrypted access via Secure Shell (SSH-only, legacy protocols disabled)",
			},
			{
				ID:      "SYS.1.3.A10",
				Title:   "Verhinderung der Ausbreitung bei Schwachstellen",
				Level:   "S",
				English: "Prevention of lateral movement (MAC: AppArmor / SELinux in enforcing mode)",
			},
			{
				ID:      "SYS.1.3.A14",
				Title:   "Verhinderung des Ausspähens von Systeminformationen",
				Level:   "H",
				English: "Prevention of system information leakage (dmesg, kptr, ptrace restrictions)",
			},
			{
				ID:      "SYS.1.3.A16",
				Title:   "Zusätzliche Verhinderung der Ausbreitung",
				Level:   "H",
				English: "Additional lateral-movement prevention (seccomp per service) — no automated OS check",
			},
			{
				ID:      "SYS.1.3.A17",
				Title:   "Zusätzlicher Schutz des Kernels",
				Level:   "H",
				English: "Additional kernel hardening (grsecurity / PaX) — no automated OS check",
			},
		},
	},
	{
		ID:      "SYS.1.1",
		Title:   "Allgemeiner Server",
		English: "General Server",
		Requirements: []BSIRequirement{
			{
				ID:      "SYS.1.1.A2",
				Title:   "Benutzerauthentisierung an Servern",
				Level:   "B",
				English: "User authentication on servers (PAM, sudo, session controls)",
			},
			{
				ID:      "SYS.1.1.A5",
				Title:   "Schutz von Schnittstellen",
				Level:   "B",
				English: "Interface protection (wireless disabled, removable media restricted)",
			},
			{
				ID:      "SYS.1.1.A6",
				Title:   "Deaktivierung nicht benötigter Dienste",
				Level:   "B",
				English: "Deactivation of unnecessary services and daemons",
			},
			{
				ID:      "SYS.1.1.A9",
				Title:   "Einsatz von Virenschutz-Programmen",
				Level:   "B",
				English: "Use of antivirus/malware protection — no direct OS-level check",
			},
			{
				ID:      "SYS.1.1.A10",
				Title:   "Protokollierung",
				Level:   "B",
				English: "Logging of security-relevant system events (auditd, rsyslog, logrotate)",
			},
			{
				ID:      "SYS.1.1.A16",
				Title:   "Sichere Grundkonfiguration von Servern",
				Level:   "S",
				English: "Secure base configuration (network sysctls, filesystem mount hardening)",
			},
			{
				ID:      "SYS.1.1.A19",
				Title:   "Einrichtung lokaler Paketfilter",
				Level:   "S",
				English: "Local packet filter (firewall: UFW / iptables / nftables)",
			},
			{
				ID:      "SYS.1.1.A27",
				Title:   "Hostbasierte Angriffserkennung",
				Level:   "H",
				English: "Host-based intrusion detection (AIDE file integrity monitoring)",
			},
			{
				ID:      "SYS.1.1.A33",
				Title:   "Aktive Verwaltung der Wurzelzertifikate",
				Level:   "H",
				English: "Root certificate management — no automated OS-level check",
			},
			{
				ID:      "SYS.1.1.A34",
				Title:   "Festplattenverschlüsselung",
				Level:   "H",
				English: "Disk encryption (LUKS) — no automated OS-level check",
			},
			{
				ID:      "SYS.1.1.A36",
				Title:   "Absicherung des Bootvorgangs",
				Level:   "H",
				English: "Boot process hardening (Secure Boot) — no automated OS-level check",
			},
		},
	},
	{
		ID:      "OPS.1.1",
		Title:   "Ordnungsgemäße IT-Administration",
		English: "Proper IT Administration (Patch / Change / Logging)",
		Requirements: []BSIRequirement{
			{
				ID:      "OPS.1.1.3.A3",
				Title:   "Konfiguration von Autoupdate-Mechanismen",
				Level:   "S",
				English: "Configuration of auto-update mechanisms (unattended-upgrades / dnf-automatic)",
			},
			{
				ID:      "OPS.1.1.3.A10",
				Title:   "Sicherstellung der Integrität und Authentizität von Softwarepaketen",
				Level:   "B",
				English: "Package signing and authenticity verification (GPG keys, no unauthenticated packages)",
			},
			{
				ID:      "OPS.1.1.5.A4",
				Title:   "Zeitsynchronisation der IT-Systeme",
				Level:   "B",
				English: "Time synchronisation (NTP / chrony / systemd-timesyncd)",
			},
		},
	},
}

// bsiMapping maps each CIS rule ID to the set of BSI IT-Grundschutz requirement
// IDs it satisfies. A rule may appear under multiple requirements.
//
// Requirements SYS.1.3.A16, SYS.1.3.A17, SYS.1.1.A9, SYS.1.1.A33,
// SYS.1.1.A34, SYS.1.1.A36 have no CIS OS-level mappings and are omitted;
// they are displayed as UNMAPPED in the report.
var bsiMapping = map[string][]string{
	// -------------------------------------------------------------------------
	// SYS.1.3.A2 — User/Group ID management
	// UID/GID uniqueness, group integrity, root-only UID 0 (section 6.2.x)
	// -------------------------------------------------------------------------
	"6.2.1":  {"SYS.1.3.A2"},
	"6.2.3":  {"SYS.1.3.A2"},
	"6.2.4":  {"SYS.1.3.A2"},
	"6.2.5":  {"SYS.1.3.A2"},
	"6.2.6":  {"SYS.1.3.A2"},
	"6.2.7":  {"SYS.1.3.A2"},
	"6.2.8":  {"SYS.1.3.A2"},
	"6.2.9":  {"SYS.1.3.A2"},
	"6.2.17": {"SYS.1.3.A2"},
	"6.2.18": {"SYS.1.3.A2"},

	// -------------------------------------------------------------------------
	// SYS.1.3.A3 — No automatic mounting of removable media
	// Removable media mount controls (section 1.1.19-21), wireless disabled
	// -------------------------------------------------------------------------
	"1.1.19": {"SYS.1.3.A3"},
	"1.1.20": {"SYS.1.3.A3"},
	"1.1.21": {"SYS.1.3.A3"},
	"3.6.1":  {"SYS.1.3.A3", "SYS.1.1.A5"},

	// -------------------------------------------------------------------------
	// SYS.1.3.A4 — ASLR, DEP/NX, kernel attack surface reduction (section 1.5.x)
	// -------------------------------------------------------------------------
	"1.5.1":  {"SYS.1.3.A4"},
	"1.5.2":  {"SYS.1.3.A4"},
	"1.5.3":  {"SYS.1.3.A4"},
	"1.5.4":  {"SYS.1.3.A4"},
	"1.5.5":  {"SYS.1.3.A4"},
	"1.5.6":  {"SYS.1.3.A4"},
	"1.5.11": {"SYS.1.3.A4"},
	"1.5.12": {"SYS.1.3.A4"},
	"1.5.16": {"SYS.1.3.A4"},
	"1.5.17": {"SYS.1.3.A4"},
	"1.5.18": {"SYS.1.3.A4"},

	// -------------------------------------------------------------------------
	// SYS.1.3.A5 — Secure software package installation
	// Package repos, signing, AIDE integrity (sections 1.2.x, 1.3.x)
	// -------------------------------------------------------------------------
	"1.2.1": {"SYS.1.3.A5", "OPS.1.1.3.A10"},
	"1.2.2": {"SYS.1.3.A5", "OPS.1.1.3.A10"},
	"1.2.3": {"SYS.1.3.A5", "OPS.1.1.3.A10"},
	"1.2.4": {"SYS.1.3.A5", "OPS.1.1.3.A3"},
	"1.3.1": {"SYS.1.3.A5", "SYS.1.1.A27"},
	"1.3.2": {"SYS.1.3.A5", "SYS.1.1.A27"},

	// -------------------------------------------------------------------------
	// SYS.1.3.A6 — User and group management (tools, file permissions)
	// Auth file permissions, sudo installation/config (sections 5.3.x, 6.1.x)
	// -------------------------------------------------------------------------
	"5.3.1":  {"SYS.1.3.A6"},
	"5.3.2":  {"SYS.1.3.A6"},
	"5.3.3":  {"SYS.1.3.A6"},
	"6.1.1":  {"SYS.1.3.A6"},
	"6.1.2":  {"SYS.1.3.A6"},
	"6.1.3":  {"SYS.1.3.A6"},
	"6.1.9":  {"SYS.1.3.A6"},
	"6.1.10": {"SYS.1.3.A6"},
	"6.1.11": {"SYS.1.3.A6"},
	"6.1.14": {"SYS.1.3.A6"},
	"6.2.2":  {"SYS.1.3.A6"},

	// -------------------------------------------------------------------------
	// SYS.1.3.A8 — SSH-only encrypted access; legacy protocols absent
	// All SSH hardening rules (section 5.2.x), legacy client/server absence (2.2.x)
	// -------------------------------------------------------------------------
	"5.2.2":  {"SYS.1.3.A8"},
	"5.2.3":  {"SYS.1.3.A8"},
	"5.2.4":  {"SYS.1.3.A8"},
	"5.2.5":  {"SYS.1.3.A8"},
	"5.2.6":  {"SYS.1.3.A8"},
	"5.2.7":  {"SYS.1.3.A8"},
	"5.2.8":  {"SYS.1.3.A8"},
	"5.2.9":  {"SYS.1.3.A8"},
	"5.2.10": {"SYS.1.3.A8"},
	"5.2.11": {"SYS.1.3.A8"},
	"5.2.12": {"SYS.1.3.A8"},
	"5.2.13": {"SYS.1.3.A8"},
	"5.2.14": {"SYS.1.3.A8"},
	"5.2.15": {"SYS.1.3.A8"},
	"5.2.16": {"SYS.1.3.A8"},
	"5.2.17": {"SYS.1.3.A8"},
	"5.2.18": {"SYS.1.3.A8"},
	"5.2.19": {"SYS.1.3.A8"},
	"5.2.20": {"SYS.1.3.A8"},
	"5.2.21": {"SYS.1.3.A8"},
	"5.2.22": {"SYS.1.3.A8"},
	"5.2.23": {"SYS.1.3.A8"},
	"5.2.24": {"SYS.1.3.A8"},
	"5.2.25": {"SYS.1.3.A8"},
	"5.2.26": {"SYS.1.3.A8"},
	"5.2.27": {"SYS.1.3.A8"},
	"5.2.28": {"SYS.1.3.A8"},
	"5.2.29": {"SYS.1.3.A8"},
	"5.2.30": {"SYS.1.3.A8"},
	"2.2.2":  {"SYS.1.3.A8"}, // rsh client absent
	"2.2.4":  {"SYS.1.3.A8"}, // telnet client absent

	// -------------------------------------------------------------------------
	// SYS.1.3.A10 — MAC (AppArmor / SELinux) in enforcing mode (sections 1.6.x, 3.3.x)
	// -------------------------------------------------------------------------
	"1.6.1": {"SYS.1.3.A10"},
	"1.6.2": {"SYS.1.3.A10"},
	"1.6.3": {"SYS.1.3.A10"},
	"1.6.4": {"SYS.1.3.A10"},
	"3.3.1": {"SYS.1.3.A10"},
	"3.3.2": {"SYS.1.3.A10"},

	// -------------------------------------------------------------------------
	// SYS.1.3.A14 — Restrict system info leakage
	// kernel.dmesg_restrict, kptr_restrict, ptrace_scope, perf_event_paranoid;
	// log file world-readability; warning banners (no OS fingerprinting)
	// -------------------------------------------------------------------------
	"1.5.7":  {"SYS.1.3.A14"},
	"1.5.8":  {"SYS.1.3.A14"},
	"1.5.9":  {"SYS.1.3.A14"},
	"1.5.10": {"SYS.1.3.A14"},
	"1.5.14": {"SYS.1.3.A14"},
	"1.5.15": {"SYS.1.3.A14"},
	"4.2.7":  {"SYS.1.3.A14"},
	"6.1.6":  {"SYS.1.3.A14"},
	"6.1.17": {"SYS.1.3.A14"},
	"1.7.1":  {"SYS.1.3.A14"},
	"1.7.2":  {"SYS.1.3.A14"},
	"1.7.3":  {"SYS.1.3.A14"},
	"1.7.4":  {"SYS.1.3.A14"},
	"1.7.5":  {"SYS.1.3.A14"},
	"1.7.6":  {"SYS.1.3.A14"},
	"1.7.7":  {"SYS.1.3.A14"},
	"1.7.8":  {"SYS.1.3.A14"},
	"1.7.9":  {"SYS.1.3.A14"},

	// -------------------------------------------------------------------------
	// SYS.1.1.A2 — User authentication (PAM, sudo, session controls)
	// -------------------------------------------------------------------------
	"5.3.4":  {"SYS.1.1.A2"},
	"5.3.5":  {"SYS.1.1.A2"},
	"5.4.1":  {"SYS.1.1.A2"},
	"5.4.2":  {"SYS.1.1.A2"},
	"5.4.3":  {"SYS.1.1.A2"},
	"5.4.4":  {"SYS.1.1.A2"},
	"5.4.5":  {"SYS.1.1.A2"},
	"5.4.6":  {"SYS.1.1.A2"},
	"5.4.7":  {"SYS.1.1.A2"},
	"5.4.8":  {"SYS.1.1.A2"},
	"5.4.9":  {"SYS.1.1.A2"},
	"5.4.10": {"SYS.1.1.A2"},
	"5.4.11": {"SYS.1.1.A2"},
	"5.4.12": {"SYS.1.1.A2"},
	"5.4.13": {"SYS.1.1.A2"},
	"5.4.14": {"SYS.1.1.A2"},
	"5.4.15": {"SYS.1.1.A2"},
	"5.4.16": {"SYS.1.1.A2"},
	"5.4.17": {"SYS.1.1.A2"},
	"5.5.1":  {"SYS.1.1.A2"},
	"5.5.2":  {"SYS.1.1.A2"},
	"5.5.3":  {"SYS.1.1.A2"},
	"5.5.4":  {"SYS.1.1.A2"},
	"6.1.18": {"SYS.1.1.A2"},
	"6.1.19": {"SYS.1.1.A2"},
	"6.1.20": {"SYS.1.1.A2"},

	// -------------------------------------------------------------------------
	// SYS.1.1.A5 — Interface protection (wireless, filesystem modules)
	// -------------------------------------------------------------------------
	"1.1.1.1": {"SYS.1.1.A5"},
	"1.1.1.2": {"SYS.1.1.A5"},
	"1.1.1.3": {"SYS.1.1.A5"},
	"1.1.1.4": {"SYS.1.1.A5"},
	"1.1.1.5": {"SYS.1.1.A5"},
	"1.1.1.6": {"SYS.1.1.A5"},
	"1.1.1.7": {"SYS.1.1.A5"},
	// 3.6.1 already listed under SYS.1.3.A3 above (also maps to SYS.1.1.A5)

	// -------------------------------------------------------------------------
	// SYS.1.1.A6 — Deactivate unnecessary services and daemons
	// Legacy clients (2.2.x), unused server daemons (2.3.x)
	// -------------------------------------------------------------------------
	"2.2.1":  {"SYS.1.1.A6"},
	"2.2.3":  {"SYS.1.1.A6"},
	"2.2.5":  {"SYS.1.1.A6"},
	"2.3.1":  {"SYS.1.1.A6"},
	"2.3.2":  {"SYS.1.1.A6"},
	"2.3.3":  {"SYS.1.1.A6"},
	"2.3.4":  {"SYS.1.1.A6"},
	"2.3.5":  {"SYS.1.1.A6"},
	"2.3.6":  {"SYS.1.1.A6"},
	"2.3.7":  {"SYS.1.1.A6"},
	"2.3.8":  {"SYS.1.1.A6"},
	"2.3.9":  {"SYS.1.1.A6"},
	"2.3.10": {"SYS.1.1.A6"},
	"2.3.11": {"SYS.1.1.A6"},
	"2.3.12": {"SYS.1.1.A6"},
	"2.3.13": {"SYS.1.1.A6"},
	"2.3.14": {"SYS.1.1.A6"},
	"2.3.15": {"SYS.1.1.A6"},
	"2.3.16": {"SYS.1.1.A6"},
	"3.4.1":  {"SYS.1.1.A6"},
	"3.4.2":  {"SYS.1.1.A6"},
	"3.4.3":  {"SYS.1.1.A6"},
	"3.4.4":  {"SYS.1.1.A6"},
	"3.4.5":  {"SYS.1.1.A6"},

	// -------------------------------------------------------------------------
	// SYS.1.1.A10 — Logging (auditd, rsyslog, logrotate)
	// -------------------------------------------------------------------------
	"4.1.1.1": {"SYS.1.1.A10"},
	"4.1.1.2": {"SYS.1.1.A10"},
	"4.1.1.3": {"SYS.1.1.A10"},
	"4.1.1.4": {"SYS.1.1.A10"},
	"4.1.1.5": {"SYS.1.1.A10"},
	"4.1.2":   {"SYS.1.1.A10"},
	"4.1.3":   {"SYS.1.1.A10"},
	"4.1.4":   {"SYS.1.1.A10"},
	"4.1.5":   {"SYS.1.1.A10"},
	"4.1.6":   {"SYS.1.1.A10"},
	"4.1.7":   {"SYS.1.1.A10"},
	"4.1.8":   {"SYS.1.1.A10"},
	"4.1.9":   {"SYS.1.1.A10"},
	"4.1.10":  {"SYS.1.1.A10"},
	"4.1.11":  {"SYS.1.1.A10"},
	"4.1.12":  {"SYS.1.1.A10"},
	"4.1.13":  {"SYS.1.1.A10"},
	"4.1.14":  {"SYS.1.1.A10"},
	"4.1.15":  {"SYS.1.1.A10"},
	"4.1.16":  {"SYS.1.1.A10"},
	"4.1.17":  {"SYS.1.1.A10"},
	"4.2.1":   {"SYS.1.1.A10"},
	"4.2.2":   {"SYS.1.1.A10"},
	"4.2.2.2": {"SYS.1.1.A10"},
	"4.2.2.3": {"SYS.1.1.A10"},
	"4.2.3":   {"SYS.1.1.A10"},
	"4.2.4":   {"SYS.1.1.A10"},
	"4.2.5":   {"SYS.1.1.A10"},
	"4.2.6":   {"SYS.1.1.A10"},
	"4.3.1":   {"SYS.1.1.A10"},

	// -------------------------------------------------------------------------
	// SYS.1.1.A16 — Secure base configuration
	// Network sysctls (3.1.x, 3.2.x), filesystem partition hardening (1.1.x)
	// -------------------------------------------------------------------------
	"3.1.1":   {"SYS.1.1.A16"},
	"3.1.2":   {"SYS.1.1.A16"},
	"3.1.3":   {"SYS.1.1.A16"},
	"3.2.1":   {"SYS.1.1.A16"},
	"3.2.2":   {"SYS.1.1.A16"},
	"3.2.3":   {"SYS.1.1.A16"},
	"3.2.4":   {"SYS.1.1.A16"},
	"3.2.5":   {"SYS.1.1.A16"},
	"3.2.6":   {"SYS.1.1.A16"},
	"3.2.7":   {"SYS.1.1.A16"},
	"3.2.8":   {"SYS.1.1.A16"},
	"3.2.9":   {"SYS.1.1.A16"},
	"3.2.10":  {"SYS.1.1.A16"},
	"3.2.11":  {"SYS.1.1.A16"},
	"3.2.12":  {"SYS.1.1.A16"},
	"3.2.13":  {"SYS.1.1.A16"},
	"3.2.14":  {"SYS.1.1.A16"},
	"3.2.15":  {"SYS.1.1.A16"},
	"3.2.16":  {"SYS.1.1.A16"},
	"3.2.17":  {"SYS.1.1.A16"},
	"3.2.18":  {"SYS.1.1.A16"},
	"3.2.22":  {"SYS.1.1.A16"},
	"3.2.23":  {"SYS.1.1.A16"},
	"3.2.24":  {"SYS.1.1.A16"},
	"3.2.25":  {"SYS.1.1.A16"},
	"3.2.26":  {"SYS.1.1.A16"},
	"3.2.27":  {"SYS.1.1.A16"},
	"3.2.28":  {"SYS.1.1.A16"},
	"3.2.29":  {"SYS.1.1.A16"},
	"3.2.30":  {"SYS.1.1.A16"},
	"3.2.31":  {"SYS.1.1.A16"},
	"3.2.32":  {"SYS.1.1.A16"},
	"3.2.33":  {"SYS.1.1.A16"},
	"3.2.34":  {"SYS.1.1.A16"},
	"3.2.35":  {"SYS.1.1.A16"},
	"3.2.36":  {"SYS.1.1.A16"},
	"3.2.37":  {"SYS.1.1.A16"},
	"3.2.38":  {"SYS.1.1.A16"},
	"3.2.39":  {"SYS.1.1.A16"},
	"1.1.2":   {"SYS.1.1.A16"},
	"1.1.3":   {"SYS.1.1.A16"},
	"1.1.4":   {"SYS.1.1.A16"},
	"1.1.5":   {"SYS.1.1.A16"},
	"1.1.6":   {"SYS.1.1.A16"},
	"1.1.7":   {"SYS.1.1.A16"},
	"1.1.8":   {"SYS.1.1.A16"},
	"1.1.9":   {"SYS.1.1.A16"},
	"1.1.10":  {"SYS.1.1.A16"},
	"1.1.11":  {"SYS.1.1.A16"},
	"1.1.12":  {"SYS.1.1.A16"},
	"1.1.13":  {"SYS.1.1.A16"},
	"1.1.14":  {"SYS.1.1.A16"},
	"1.1.15":  {"SYS.1.1.A16"},
	"1.1.16":  {"SYS.1.1.A16"},
	"1.1.17":  {"SYS.1.1.A16"},
	"1.1.18":  {"SYS.1.1.A16"},
	"1.1.22":  {"SYS.1.1.A16"},
	"1.1.23":  {"SYS.1.1.A16"},
	"1.1.24":  {"SYS.1.1.A16"},
	"1.1.25":  {"SYS.1.1.A16"},
	"1.1.26":  {"SYS.1.1.A16"},
	"1.1.27":  {"SYS.1.1.A16"},
	"1.1.28":  {"SYS.1.1.A16"},
	"1.1.29":  {"SYS.1.1.A16"},
	"1.1.30":  {"SYS.1.1.A16"},
	"1.1.31":  {"SYS.1.1.A16"},
	"1.1.32":  {"SYS.1.1.A16"},
	"6.1.23":  {"SYS.1.1.A16"},
	"6.1.24":  {"SYS.1.1.A16"},
	"6.1.25":  {"SYS.1.1.A16"},
	"6.1.26":  {"SYS.1.1.A16"},
	"6.1.27":  {"SYS.1.1.A16"},
	"6.1.28":  {"SYS.1.1.A16"},
	"6.1.29":  {"SYS.1.1.A16"},
	"6.1.30":  {"SYS.1.1.A16"},
	"6.1.31":  {"SYS.1.1.A16"},
	"6.1.32":  {"SYS.1.1.A16"},
	"6.1.33":  {"SYS.1.1.A16"},
	"6.1.34":  {"SYS.1.1.A16"},
	"6.1.35":  {"SYS.1.1.A16"},
	"6.1.36":  {"SYS.1.1.A16"},
	"6.1.37":  {"SYS.1.1.A16"},
	"6.1.38":  {"SYS.1.1.A16"},
	"6.2.10":  {"SYS.1.1.A16"},
	"6.2.11":  {"SYS.1.1.A16"},
	"6.2.12":  {"SYS.1.1.A16"},
	"6.2.13":  {"SYS.1.1.A16"},
	"6.2.14":  {"SYS.1.1.A16"},
	"6.2.15":  {"SYS.1.1.A16"},
	"6.2.16":  {"SYS.1.1.A16"},

	// -------------------------------------------------------------------------
	// SYS.1.1.A19 — Local packet filter (UFW / iptables / nftables)
	// -------------------------------------------------------------------------
	"3.5.1":     {"SYS.1.1.A19"},
	"3.5.1.1":   {"SYS.1.1.A19"},
	"3.5.1.2":   {"SYS.1.1.A19"},
	"3.5.1.3":   {"SYS.1.1.A19"},
	"3.5.1.4":   {"SYS.1.1.A19"},
	"3.5.1.5":   {"SYS.1.1.A19"},
	"3.5.1.6":   {"SYS.1.1.A19"},
	"3.5.1.7":   {"SYS.1.1.A19"},

	// -------------------------------------------------------------------------
	// SYS.1.1.A27 — Host-based intrusion detection (AIDE file integrity)
	// -------------------------------------------------------------------------
	// 1.3.1 and 1.3.2 already listed under SYS.1.3.A5; AIDE also satisfies A27

	// -------------------------------------------------------------------------
	// OPS.1.1.3.A3 — Auto-update (1.2.4 already listed under SYS.1.3.A5)
	// OPS.1.1.3.A10 — Package signing (1.2.1-1.2.3 already listed under SYS.1.3.A5)
	// -------------------------------------------------------------------------

	// -------------------------------------------------------------------------
	// OPS.1.1.5.A4 — Time synchronisation
	// -------------------------------------------------------------------------
	"2.1.1": {"OPS.1.1.5.A4"},
	"2.1.2": {"OPS.1.1.5.A4"},
}

// BSIRefs returns the BSI requirement IDs that the given CIS rule ID satisfies.
// Returns nil if the rule is not mapped to any BSI requirement.
func BSIRefs(cisID string) []string {
	return bsiMapping[cisID]
}

// BSIReqGroup holds all CIS results evaluated against one BSI requirement.
type BSIReqGroup struct {
	Req      BSIRequirement
	Baustein BSIBaustein
	Status   string // "PASS"|"PARTIAL"|"FAIL"|"SKIP"|"UNMAPPED"
	Pass     int
	Fail     int
	Manual   int
	Skipped  int
	Results  []models.CISResult
}

// GroupByBSI groups CIS evaluation results by BSI IT-Grundschutz requirement.
// It returns one group per requirement across all included building blocks, in
// building-block declaration order. Requirements with no CIS mapping produce an
// UNMAPPED group with an empty Results slice.
func GroupByBSI(results []models.CISResult) []BSIReqGroup {
	// Index results by BSI req ID for fast lookup.
	byReq := make(map[string][]models.CISResult)
	for _, r := range results {
		for _, ref := range r.BSIRefs {
			byReq[ref] = append(byReq[ref], r)
		}
	}

	var groups []BSIReqGroup
	for _, baustein := range BSIBausteine {
		for _, req := range baustein.Requirements {
			matched := byReq[req.ID]
			g := BSIReqGroup{
				Req:      req,
				Baustein: baustein,
				Results:  matched,
			}
			if len(matched) == 0 {
				g.Status = "UNMAPPED"
				groups = append(groups, g)
				continue
			}
			for _, r := range matched {
				switch r.Status {
				case models.CISPass:
					g.Pass++
				case models.CISFail:
					g.Fail++
				case models.CISManual:
					g.Manual++
				default:
					g.Skipped++
				}
			}
			switch {
			case g.Fail > 0 && g.Pass == 0 && g.Manual == 0:
				g.Status = "FAIL"
			case g.Fail > 0:
				g.Status = "PARTIAL"
			case g.Pass > 0:
				g.Status = "PASS"
			default:
				g.Status = "SKIP"
			}
			groups = append(groups, g)
		}
	}
	return groups
}
