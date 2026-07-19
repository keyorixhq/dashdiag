package cis

import "github.com/keyorixhq/dashdiag/internal/models"

const (
	nis2ArticleB = "Art.21(2)(b)"
	nis2ArticleD = "Art.21(2)(d)"
	nis2ArticleE = "Art.21(2)(e)"
	nis2ArticleG = "Art.21(2)(g)"
	nis2ArticleH = "Art.21(2)(h)"
	nis2ArticleI = "Art.21(2)(i)"
	nis2ArticleJ = "Art.21(2)(j)"
)

// NIS2Article21 describes one sub-item of NIS2 Directive Article 21(2).
type NIS2Article21 struct {
	ID    string // e.g. nis2ArticleB
	Title string // short label e.g. "Incident handling"
	Scope string // one-line scope note from the Directive
}

// NIS2Articles lists all 10 sub-items of Article 21(2) in directive order.
// Articles (a), (c), (f) have zero CIS OS-level mappings and produce UNMAPPED
// groups; they are included so the report always presents all 10 items.
var NIS2Articles = []NIS2Article21{
	{
		ID:    "Art.21(2)(a)",
		Title: "Risk analysis",
		Scope: "Policies on risk analysis and information system security",
	},
	{
		ID:    nis2ArticleB,
		Title: "Incident handling",
		Scope: "Detection, reporting and response to cybersecurity incidents",
	},
	{
		ID:    "Art.21(2)(c)",
		Title: "Business continuity",
		Scope: "Backup management, disaster recovery and crisis management",
	},
	{
		ID:    nis2ArticleD,
		Title: "Supply chain security",
		Scope: "Security in the supply chain including software and third-party components",
	},
	{
		ID:    nis2ArticleE,
		Title: "Security in acquisition",
		Scope: "Security in network and information systems acquisition, development and maintenance",
	},
	{
		ID:    "Art.21(2)(f)",
		Title: "Assess effectiveness",
		Scope: "Policies and procedures to assess cybersecurity risk management measure effectiveness",
	},
	{
		ID:    nis2ArticleG,
		Title: "Cyber hygiene",
		Scope: "Basic cyber hygiene practices and cybersecurity training",
	},
	{
		ID:    nis2ArticleH,
		Title: "Cryptography",
		Scope: "Policies and procedures regarding the use of cryptography and encryption",
	},
	{
		ID:    nis2ArticleI,
		Title: "Access control",
		Scope: "Human resources security, access control policies and asset management",
	},
	{
		ID:    nis2ArticleJ,
		Title: "Secured communications",
		Scope: "MFA, secured voice/video/text communications and secured emergency communications",
	},
}

// NIS2ArticleByID returns the NIS2Article21 for the given ID (e.g. nis2ArticleB).
func NIS2ArticleByID(id string) (NIS2Article21, bool) {
	for _, a := range NIS2Articles {
		if a.ID == id {
			return a, true
		}
	}
	return NIS2Article21{}, false
}

// nis2Mapping maps each CIS rule ID to the set of NIS2 Article 21(2) sub-items
// it satisfies. A rule may appear under multiple articles.
//
// Articles (a), (c), (f) have no OS-level CIS rule mapping and are omitted here.
var nis2Mapping = map[string][]string{
	// -------------------------------------------------------------------------
	// Art.21(2)(b) — Incident Handling
	// Audit subsystem configuration (section 4.1.x)
	// -------------------------------------------------------------------------
	"4.1.1.1": {nis2ArticleB},
	"4.1.1.2": {nis2ArticleB},
	"4.1.1.3": {nis2ArticleB},
	"4.1.1.4": {nis2ArticleB},
	"4.1.1.5": {nis2ArticleB},
	"4.1.2":   {nis2ArticleB},
	"4.1.3":   {nis2ArticleB},
	"4.1.4":   {nis2ArticleB},
	"4.1.5":   {nis2ArticleB},
	"4.1.6":   {nis2ArticleB},
	"4.1.7":   {nis2ArticleB},
	"4.1.8":   {nis2ArticleB},
	"4.1.9":   {nis2ArticleB},
	"4.1.10":  {nis2ArticleB},
	"4.1.11":  {nis2ArticleB},
	"4.1.12":  {nis2ArticleB},
	"4.1.13":  {nis2ArticleB},
	"4.1.14":  {nis2ArticleB},
	"4.1.15":  {nis2ArticleB},
	"4.1.16":  {nis2ArticleB},
	"4.1.17":  {nis2ArticleB},
	// Logging configuration (section 4.2.x / 4.3.x)
	"4.2.1":   {nis2ArticleB},
	"4.2.2":   {nis2ArticleB},
	"4.2.2.2": {nis2ArticleB},
	"4.2.2.3": {nis2ArticleB},
	"4.2.3":   {nis2ArticleB},
	"4.2.4":   {nis2ArticleB},
	"4.2.5":   {nis2ArticleB},
	"4.2.6":   {nis2ArticleB},
	"4.2.7":   {nis2ArticleB},
	"4.3.1":   {nis2ArticleB},

	// -------------------------------------------------------------------------
	// Art.21(2)(d) — Supply Chain Security
	// Package integrity and update channels (section 1.2.x)
	// -------------------------------------------------------------------------
	"1.2.1": {nis2ArticleD},
	"1.2.2": {nis2ArticleD},
	"1.2.3": {nis2ArticleD},
	"1.2.4": {nis2ArticleD},
	// File integrity monitoring (section 1.3.x)
	"1.3.1": {nis2ArticleD},
	"1.3.2": {nis2ArticleD},

	// -------------------------------------------------------------------------
	// Art.21(2)(e) — Security in Acquisition/Development
	// Filesystem module controls (section 1.1.1.x)
	// -------------------------------------------------------------------------
	"1.1.1.1": {nis2ArticleE},
	"1.1.1.2": {nis2ArticleE},
	"1.1.1.3": {nis2ArticleE},
	"1.1.1.4": {nis2ArticleE},
	"1.1.1.5": {nis2ArticleE},
	"1.1.1.6": {nis2ArticleE},
	"1.1.1.7": {nis2ArticleE},
	// Kernel hardening / attack surface reduction (section 1.5.x)
	"1.5.1":  {nis2ArticleE},
	"1.5.2":  {nis2ArticleE},
	"1.5.3":  {nis2ArticleE},
	"1.5.4":  {nis2ArticleE},
	"1.5.5":  {nis2ArticleE},
	"1.5.6":  {nis2ArticleE},
	"1.5.7":  {nis2ArticleE},
	"1.5.8":  {nis2ArticleE},
	"1.5.9":  {nis2ArticleE},
	"1.5.10": {nis2ArticleE},
	"1.5.11": {nis2ArticleE},
	"1.5.12": {nis2ArticleE},
	"1.5.14": {nis2ArticleE},
	"1.5.15": {nis2ArticleE},
	"1.5.16": {nis2ArticleE},
	"1.5.17": {nis2ArticleE},
	"1.5.18": {nis2ArticleE},
	// Mandatory Access Control (section 1.6.x)
	"1.6.1": {nis2ArticleE},
	"1.6.2": {nis2ArticleE},
	"1.6.3": {nis2ArticleE},
	"1.6.4": {nis2ArticleE},
	// Uncommon/dangerous network protocols disabled (section 3.4.x)
	"3.4.1": {nis2ArticleE},
	"3.4.2": {nis2ArticleE},
	"3.4.3": {nis2ArticleE},
	"3.4.4": {nis2ArticleE},
	"3.4.5": {nis2ArticleE},
	// Wireless disabled (section 3.6.x)
	"3.6.1": {nis2ArticleE},

	// -------------------------------------------------------------------------
	// Art.21(2)(g) — Cyber Hygiene
	// Time synchronization (section 2.1.x)
	// -------------------------------------------------------------------------
	"2.1.1": {nis2ArticleG},
	"2.1.2": {nis2ArticleG},
	// Legacy/risky client software removed (section 2.2.x)
	"2.2.1": {nis2ArticleG},
	"2.2.2": {nis2ArticleG},
	"2.2.3": {nis2ArticleG},
	"2.2.4": {nis2ArticleG},
	"2.2.5": {nis2ArticleG},
	// Unnecessary server daemons not installed (section 2.3.x)
	"2.3.1":  {nis2ArticleG},
	"2.3.2":  {nis2ArticleG},
	"2.3.3":  {nis2ArticleG},
	"2.3.4":  {nis2ArticleG},
	"2.3.5":  {nis2ArticleG},
	"2.3.6":  {nis2ArticleG},
	"2.3.7":  {nis2ArticleG},
	"2.3.8":  {nis2ArticleG},
	"2.3.9":  {nis2ArticleG},
	"2.3.10": {nis2ArticleG},
	"2.3.11": {nis2ArticleG},
	"2.3.12": {nis2ArticleG},
	"2.3.13": {nis2ArticleG},
	"2.3.14": {nis2ArticleG},
	"2.3.15": {nis2ArticleG},
	"2.3.16": {nis2ArticleG},
	// Network hardening — no source routing, no redirects, etc. (section 3.1.x–3.3.x)
	"3.1.1":  {nis2ArticleG},
	"3.1.2":  {nis2ArticleG},
	"3.1.3":  {nis2ArticleG},
	"3.2.1":  {nis2ArticleG},
	"3.2.2":  {nis2ArticleG},
	"3.2.3":  {nis2ArticleG},
	"3.2.4":  {nis2ArticleG},
	"3.2.5":  {nis2ArticleG},
	"3.2.6":  {nis2ArticleG},
	"3.2.7":  {nis2ArticleG},
	"3.2.8":  {nis2ArticleG},
	"3.2.9":  {nis2ArticleG},
	"3.2.10": {nis2ArticleG},
	"3.2.11": {nis2ArticleG},
	"3.2.12": {nis2ArticleG},
	"3.2.13": {nis2ArticleG},
	"3.2.14": {nis2ArticleG},
	"3.2.15": {nis2ArticleG},
	"3.2.16": {nis2ArticleG},
	"3.2.17": {nis2ArticleG},
	"3.2.18": {nis2ArticleG},
	"3.2.22": {nis2ArticleG},
	"3.2.23": {nis2ArticleG},
	"3.2.24": {nis2ArticleG},
	"3.2.25": {nis2ArticleG},
	"3.2.26": {nis2ArticleG},
	"3.2.27": {nis2ArticleG},
	"3.2.28": {nis2ArticleG},
	"3.2.29": {nis2ArticleG},
	"3.2.30": {nis2ArticleG},
	"3.2.31": {nis2ArticleG},
	"3.2.32": {nis2ArticleG},
	"3.2.33": {nis2ArticleG},
	"3.2.34": {nis2ArticleG},
	"3.2.35": {nis2ArticleG},
	"3.2.36": {nis2ArticleG},
	"3.2.37": {nis2ArticleG},
	"3.2.38": {nis2ArticleG},
	"3.2.39": {nis2ArticleG},
	"3.3.1":  {nis2ArticleG},
	"3.3.2":  {nis2ArticleG},
	// SSH general hardening — non-crypto, non-auth rules (section 5.2.x selected)
	"5.2.2":  {nis2ArticleG},
	"5.2.6":  {nis2ArticleG},
	"5.2.7":  {nis2ArticleG},
	"5.2.8":  {nis2ArticleG},
	"5.2.9":  {nis2ArticleG},
	"5.2.10": {nis2ArticleG},
	"5.2.11": {nis2ArticleG},
	"5.2.12": {nis2ArticleG},
	"5.2.13": {nis2ArticleG},
	"5.2.15": {nis2ArticleG},
	"5.2.18": {nis2ArticleG},
	"5.2.19": {nis2ArticleG},
	"5.2.21": {nis2ArticleG},
	"5.2.22": {nis2ArticleG},
	"5.2.23": {nis2ArticleG},
	"5.2.24": {nis2ArticleG},
	"5.2.28": {nis2ArticleG},
	"5.2.29": {nis2ArticleG},
	"5.2.30": {nis2ArticleG},
	// Password quality — basic hygiene rules (section 5.4.x selected)
	"5.4.1":  {nis2ArticleG},
	"5.4.9":  {nis2ArticleG},
	"5.4.15": {nis2ArticleG},
	"5.4.16": {nis2ArticleG},
	"5.4.17": {nis2ArticleG},
	// Warning banners — user awareness (section 1.7.x)
	"1.7.1": {nis2ArticleG},
	"1.7.2": {nis2ArticleG},
	"1.7.3": {nis2ArticleG},
	"1.7.4": {nis2ArticleG},
	"1.7.5": {nis2ArticleG},
	"1.7.6": {nis2ArticleG},
	"1.7.7": {nis2ArticleG},
	"1.7.8": {nis2ArticleG},
	"1.7.9": {nis2ArticleG},

	// -------------------------------------------------------------------------
	// Art.21(2)(h) — Cryptography
	// SSH cipher/MAC/KEX algorithms (section 5.2.x selected)
	// -------------------------------------------------------------------------
	"5.2.3":  {nis2ArticleH},
	"5.2.4":  {nis2ArticleH},
	"5.2.5":  {nis2ArticleH},
	"5.2.25": {nis2ArticleH},
	"5.2.26": {nis2ArticleH},
	"5.2.27": {nis2ArticleH},
	// Password hashing algorithm — also (g); primary home is (h)
	"5.4.11": {nis2ArticleH, nis2ArticleG},
	// GRUB boot security — protects key material at boot (section 1.4.x)
	"1.4.1": {nis2ArticleH},
	"1.4.2": {nis2ArticleH},

	// -------------------------------------------------------------------------
	// Art.21(2)(i) — Access Control and Asset Management
	// Cron/at scheduling access control (section 5.1.x)
	// -------------------------------------------------------------------------
	"5.1.1":  {nis2ArticleI},
	"5.1.2":  {nis2ArticleI},
	"5.1.3":  {nis2ArticleI},
	"5.1.4":  {nis2ArticleI},
	"5.1.5":  {nis2ArticleI},
	"5.1.6":  {nis2ArticleI},
	"5.1.7":  {nis2ArticleI},
	"5.1.8":  {nis2ArticleI},
	"5.1.9":  {nis2ArticleI},
	"5.1.10": {nis2ArticleI},
	"5.1.11": {nis2ArticleI},
	"5.1.12": {nis2ArticleI},
	"5.1.13": {nis2ArticleI},
	"5.1.14": {nis2ArticleI},
	"5.1.15": {nis2ArticleI},
	"5.1.16": {nis2ArticleI},
	"5.1.17": {nis2ArticleI},
	"5.1.18": {nis2ArticleI},
	"5.1.19": {nis2ArticleI},
	"5.1.20": {nis2ArticleI},
	"5.1.21": {nis2ArticleI},
	"5.1.22": {nis2ArticleI},
	"5.1.23": {nis2ArticleI},
	// Sudo — privilege escalation control (section 5.3.x)
	"5.3.1": {nis2ArticleI},
	"5.3.2": {nis2ArticleI},
	"5.3.3": {nis2ArticleI},
	"5.3.4": {nis2ArticleI},
	"5.3.5": {nis2ArticleI},
	// Password aging and account management (section 5.4.x selected)
	"5.4.2": {nis2ArticleI},
	"5.4.3": {nis2ArticleI},
	"5.4.4": {nis2ArticleI},
	"5.4.5": {nis2ArticleI},
	"5.4.6": {nis2ArticleI},
	"5.4.7": {nis2ArticleI},
	"5.4.8": {nis2ArticleI},
	// SSH privilege rules — also (j); primary home is (i)
	"5.2.14": {nis2ArticleI, nis2ArticleJ},
	"5.2.16": {nis2ArticleI, nis2ArticleG},
	// File permissions — system file asset protection (section 6.1.x)
	"6.1.1":  {nis2ArticleI},
	"6.1.2":  {nis2ArticleI},
	"6.1.3":  {nis2ArticleI},
	"6.1.4":  {nis2ArticleI},
	"6.1.5":  {nis2ArticleI},
	"6.1.6":  {nis2ArticleI},
	"6.1.7":  {nis2ArticleI},
	"6.1.8":  {nis2ArticleI},
	"6.1.9":  {nis2ArticleI},
	"6.1.10": {nis2ArticleI},
	"6.1.11": {nis2ArticleI},
	"6.1.12": {nis2ArticleI},
	"6.1.13": {nis2ArticleI},
	"6.1.14": {nis2ArticleI},
	"6.1.15": {nis2ArticleI},
	"6.1.16": {nis2ArticleI},
	"6.1.17": {nis2ArticleI},
	"6.1.18": {nis2ArticleI},
	"6.1.19": {nis2ArticleI},
	"6.1.20": {nis2ArticleI},
	"6.1.21": {nis2ArticleI},
	"6.1.22": {nis2ArticleI},
	"6.1.23": {nis2ArticleI},
	"6.1.24": {nis2ArticleI},
	"6.1.25": {nis2ArticleI},
	"6.1.26": {nis2ArticleI},
	"6.1.27": {nis2ArticleI},
	"6.1.28": {nis2ArticleI},
	"6.1.29": {nis2ArticleI},
	"6.1.30": {nis2ArticleI},
	"6.1.31": {nis2ArticleI},
	"6.1.32": {nis2ArticleI},
	"6.1.33": {nis2ArticleI},
	"6.1.34": {nis2ArticleI},
	"6.1.35": {nis2ArticleI},
	"6.1.36": {nis2ArticleI},
	"6.1.37": {nis2ArticleI},
	"6.1.38": {nis2ArticleI},
	// User account integrity (section 6.2.x)
	"6.2.1":  {nis2ArticleI},
	"6.2.2":  {nis2ArticleI},
	"6.2.3":  {nis2ArticleI},
	"6.2.4":  {nis2ArticleI},
	"6.2.5":  {nis2ArticleI},
	"6.2.6":  {nis2ArticleI},
	"6.2.7":  {nis2ArticleI},
	"6.2.8":  {nis2ArticleI},
	"6.2.9":  {nis2ArticleI},
	"6.2.10": {nis2ArticleI},
	"6.2.11": {nis2ArticleI},
	"6.2.12": {nis2ArticleI},
	"6.2.13": {nis2ArticleI},
	"6.2.14": {nis2ArticleI},
	"6.2.15": {nis2ArticleI},
	"6.2.16": {nis2ArticleI},
	"6.2.17": {nis2ArticleI},
	"6.2.18": {nis2ArticleI},
	// Firewall — network access control (section 3.5.x)
	"3.5.1":   {nis2ArticleI},
	"3.5.1.1": {nis2ArticleI},
	"3.5.1.2": {nis2ArticleI},
	"3.5.1.3": {nis2ArticleI},
	"3.5.1.4": {nis2ArticleI},
	"3.5.1.5": {nis2ArticleI},
	"3.5.1.6": {nis2ArticleI},
	"3.5.1.7": {nis2ArticleI},

	// -------------------------------------------------------------------------
	// Art.21(2)(j) — Secured Communications / MFA
	// SSH auth controls — key-only auth is the strongest available MFA substitute
	// on Linux (section 5.2.x selected)
	// -------------------------------------------------------------------------
	// 5.2.14 already entered above with dual refs (i) + (j)
	"5.2.17": {nis2ArticleJ},
	"5.2.20": {nis2ArticleJ},
	// PAM account lockout — brute-force protection (section 5.4.x selected)
	"5.4.10": {nis2ArticleJ},
	"5.4.13": {nis2ArticleJ},
	"5.4.14": {nis2ArticleJ},
	// PAM password complexity — also (g); primary home is (j)
	"5.4.12": {nis2ArticleJ, nis2ArticleG},
	// Session controls (section 5.5.x)
	"5.5.1": {nis2ArticleJ},
	"5.5.2": {nis2ArticleJ},
	"5.5.3": {nis2ArticleJ},
	"5.5.4": {nis2ArticleJ},
}

// NIS2Refs returns the NIS2 Article 21(2) sub-item IDs that the given CIS rule
// ID maps to. Returns nil when the rule has no NIS2 mapping.
func NIS2Refs(cisID string) []string {
	return nis2Mapping[cisID]
}

// NIS2ArticleGroup aggregates CISResults that belong to one NIS2 article.
type NIS2ArticleGroup struct {
	Article NIS2Article21
	Status  string // "PASS" | "PARTIAL" | "FAIL" | "SKIP" | "UNMAPPED"
	Pass    int
	Fail    int
	Manual  int
	Skipped int
	Results []models.CISResult
}

// GroupByNIS2 groups a slice of CISResults by their NIS2Refs, returning one
// NIS2ArticleGroup per article in NIS2Articles order.
//
// Status derivation:
//   - UNMAPPED — no results map to this article at all
//   - FAIL     — one or more failures and zero passes (all failing)
//   - PARTIAL  — has both passes and failures (mixed)
//   - PASS     — at least one pass and zero failures
//   - SKIP     — no passes or failures, but some skipped/manual results
func GroupByNIS2(results []models.CISResult) []NIS2ArticleGroup {
	// Build a per-article bucket from results that carry NIS2Refs.
	type bucket struct {
		pass    int
		fail    int
		manual  int
		skipped int
		results []models.CISResult
	}
	buckets := make(map[string]*bucket, len(NIS2Articles))
	for _, a := range NIS2Articles {
		buckets[a.ID] = &bucket{}
	}

	for _, r := range results {
		for _, ref := range r.NIS2Refs {
			b, ok := buckets[ref]
			if !ok {
				continue
			}
			b.results = append(b.results, r)
			switch r.Status {
			case models.CISPass:
				b.pass++
			case models.CISFail:
				b.fail++
			case models.CISManual:
				b.manual++
			case models.CISSkipped, models.CISNotApplicable:
				b.skipped++
			}
		}
	}

	groups := make([]NIS2ArticleGroup, 0, len(NIS2Articles))
	for _, a := range NIS2Articles {
		b := buckets[a.ID]
		g := NIS2ArticleGroup{
			Article: a,
			Pass:    b.pass,
			Fail:    b.fail,
			Manual:  b.manual,
			Skipped: b.skipped,
			Results: b.results,
		}

		switch {
		case len(b.results) == 0:
			g.Status = "UNMAPPED"
		case b.fail > 0 && b.pass > 0:
			g.Status = "PARTIAL"
		case b.fail > 0:
			g.Status = "FAIL"
		case b.pass > 0:
			g.Status = "PASS"
		default:
			g.Status = "SKIP"
		}

		groups = append(groups, g)
	}
	return groups
}
