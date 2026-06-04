package cmd

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
)

var tlsCmd = &cobra.Command{
	Use:   "tls [path...]",
	Short: "Check TLS certificate expiry on local files and well-known paths",
	Long: `Scan local certificate files for expiry and report certificates
expiring within warning/critical windows.

Auto-detects certificates in common locations:
  /etc/letsencrypt/live/*/cert.pem
  /etc/nginx/ssl/*.{crt,pem}
  /etc/apache2/ssl/*.{crt,pem}
  /etc/ssl/private/*.{crt,pem}
  /etc/pki/tls/certs/*.{crt,pem}
  ~/.dsd/certs/*.{crt,pem}

Or pass explicit paths:
  dsd tls /etc/nginx/ssl/example.crt /path/to/cert.pem`,
	RunE: runTLS,
}

func init() {
	rootCmd.AddCommand(tlsCmd)
	tlsCmd.Flags().Int("warn-days", 30, "warn when cert expires within N days")
	tlsCmd.Flags().Int("crit-days", 7, "critical when cert expires within N days")
	tlsCmd.Flags().Bool("all", false, "show all certs including healthy ones")
	tlsCmd.Flags().StringArray("endpoint", nil, "remote TLS endpoint to check (host:port)")
	tlsCmd.Flags().String("endpoints-file", "", "file with newline-separated host:port endpoints")
}

type certResult struct {
	Path       string
	Subject    string
	Expiry     time.Time
	DaysLeft   int
	Level      string // OK, WARN, CRIT, ERR
	Err        string
	Remote     bool // true when from a --endpoint / --endpoints-file scan
	SelfSigned bool
}

func runTLS(cmd *cobra.Command, args []string) error {
	warnDays, _ := cmd.Flags().GetInt("warn-days")
	critDays, _ := cmd.Flags().GetInt("crit-days")
	showAll, _ := cmd.Flags().GetBool("all")
	endpoints, _ := cmd.Flags().GetStringArray("endpoint")
	endpointsFile, _ := cmd.Flags().GetString("endpoints-file")
	jsonOut, _ := cmd.Flags().GetBool("json")

	// Remote endpoints: --endpoint flags first, then file lines.
	remotes := append([]string{}, endpoints...)
	remotes = append(remotes, readEndpointsFile(endpointsFile)...)

	// Collect local paths to scan. Only auto-detect when no remote endpoints and
	// no explicit paths were given — otherwise an empty local set is fine.
	paths := args
	if len(paths) == 0 && len(remotes) == 0 {
		paths = autoDetectCertPaths()
	}

	if len(paths) == 0 && len(remotes) == 0 {
		fmt.Println("no certificates found — pass paths explicitly or configure ~/.dsd/certs/")
		return nil
	}

	// Scan local paths.
	var results []certResult
	for _, p := range paths {
		res := scanCertFile(p, warnDays, critDays)
		results = append(results, res...)
	}

	// Scan remote endpoints (leaf cert only, matching the local one-line-per-file form).
	results = append(results, scanRemoteEndpoints(remotes, warnDays, critDays)...)

	if jsonOut {
		return outputJSON(os.Stdout, buildTLSInfo(results, remotes, warnDays))
	}

	if len(results) == 0 {
		fmt.Println("no certificates found in scanned paths or endpoints")
		return nil
	}

	renderTLSResults(results, showAll)
	return nil
}

// renderTLSResults sorts, prints, and summarizes scan results. It calls
// os.Exit(2) when any cert is CRIT and os.Exit(1) when any is WARN — matching
// the original dsd tls exit-code contract.
func renderTLSResults(results []certResult, showAll bool) {
	// Sort: CRIT first, then WARN, then OK, then ERR
	order := map[string]int{"CRIT": 0, "WARN": 1, "OK": 2, "ERR": 3}
	sort.Slice(results, func(i, j int) bool {
		if order[results[i].Level] != order[results[j].Level] {
			return order[results[i].Level] < order[results[j].Level]
		}
		return results[i].DaysLeft < results[j].DaysLeft
	})

	sep := strings.Repeat("─", 60)
	fmt.Printf("\n%s\n", sep)
	fmt.Printf("TLS certificate health — %d certificate(s) found\n", len(results))
	fmt.Printf("%s\n\n", sep)

	crits, warns, oks := 0, 0, 0
	for _, r := range results {
		switch r.Level {
		case "CRIT":
			crits++
		case "WARN":
			warns++
		case "OK":
			oks++
		}
		if !showAll && r.Level == "OK" {
			continue
		}
		printCertResult(r)
	}

	// Summary
	fmt.Printf("%s\n", sep)
	if crits > 0 {
		fmt.Printf("❌  %d CRIT  ⚠️  %d WARN  ✅  %d OK\n", crits, warns, oks)
		os.Exit(2)
	}
	if warns > 0 {
		fmt.Printf("⚠️   %d WARN  ✅  %d OK\n", warns, oks)
		os.Exit(1)
	}
	fmt.Printf("✅  All %d certificate(s) healthy\n", oks)
	if !showAll {
		fmt.Println("    (use --all to show individual certs)")
	}
}

// printCertResult prints a single cert/endpoint result block.
func printCertResult(r certResult) {
	icon := levelIcon(r.Level)
	tag := ""
	if r.Remote {
		tag = "  [remote]"
	}
	if r.SelfSigned {
		tag += "  [self-signed]"
	}
	fmt.Printf("%s  %s%s\n", icon, r.Path, tag)
	if r.Err != "" {
		fmt.Printf("   error: %s\n", r.Err)
		return
	}
	fmt.Printf("   Subject:  %s\n", r.Subject)
	fmt.Printf("   Expires:  %s", r.Expiry.Format("2006-01-02"))
	if r.DaysLeft <= 0 {
		fmt.Printf(" (EXPIRED %d days ago)\n", -r.DaysLeft)
	} else {
		fmt.Printf(" (%d days)\n", r.DaysLeft)
	}
	fmt.Println()
}

func scanCertFile(path string, warnDays, critDays int) []certResult {
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- user-provided or auto-detected paths
	if err != nil {
		return []certResult{{Path: path, Level: "ERR", Err: err.Error()}}
	}

	var results []certResult
	now := time.Now()

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			results = append(results, certResult{
				Path:  path,
				Level: "ERR",
				Err:   fmt.Sprintf("parse error: %v", err),
			})
			continue
		}

		daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
		level := "OK"
		switch {
		case daysLeft <= critDays:
			level = "CRIT"
		case daysLeft <= warnDays:
			level = "WARN"
		}

		subject := cert.Subject.CommonName
		if subject == "" {
			subject = cert.Subject.String()
		}

		results = append(results, certResult{
			Path:     path,
			Subject:  subject,
			Expiry:   cert.NotAfter,
			DaysLeft: daysLeft,
			Level:    level,
		})
		break // take first cert per file — leaf cert
	}

	if len(results) == 0 {
		// No CERTIFICATE block found — likely a key file, skip silently
		return nil
	}
	return results
}

// autoDetectCertPaths finds certificates in common locations.
func autoDetectCertPaths() []string {
	patterns := []string{
		"/etc/letsencrypt/live/*/cert.pem",
		"/etc/letsencrypt/live/*/fullchain.pem",
		"/etc/nginx/ssl/*.crt",
		"/etc/nginx/ssl/*.pem",
		"/etc/nginx/*.crt",
		"/etc/apache2/ssl/*.crt",
		"/etc/apache2/ssl/*.pem",
		"/etc/ssl/private/*.crt",
		"/etc/ssl/private/*.pem",
		"/etc/pki/tls/certs/*.crt",
		"/etc/pki/tls/private/*.crt",
	}

	// User-configured cert dir
	home, _ := os.UserHomeDir()
	if home != "" {
		patterns = append(patterns,
			filepath.Join(home, ".dsd", "certs", "*.crt"),
			filepath.Join(home, ".dsd", "certs", "*.pem"),
		)
	}

	var paths []string
	seen := make(map[string]bool)
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				paths = append(paths, m)
			}
		}
	}
	return paths
}

func levelIcon(level string) string {
	switch level {
	case "CRIT":
		return "❌"
	case "WARN":
		return "⚠️ "
	case "OK":
		return "✅"
	default:
		return "ℹ️ "
	}
}

// readEndpointsFile reads newline-separated host:port endpoints from path.
// Blank lines and lines starting with '#' are skipped. Missing path → nil.
func readEndpointsFile(path string) []string {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// scanRemoteEndpoints dials each endpoint, reads the leaf certificate, and
// converts it to a certResult using the same warn/crit day thresholds as local
// certs. A dial/handshake failure becomes an ERR result so the user still sees it.
func scanRemoteEndpoints(remotes []string, warnDays, critDays int) []certResult {
	if len(remotes) == 0 {
		return nil
	}
	ctx := context.Background()
	var out []certResult
	for _, ep := range remotes {
		ep = strings.TrimSpace(ep)
		if ep == "" {
			continue
		}
		certs, err := collectors.CheckRemoteEndpoint(ctx, ep)
		if err != nil || len(certs) == 0 {
			msg := "no certificates returned"
			if err != nil {
				msg = err.Error()
			}
			out = append(out, certResult{Path: ep, Level: "ERR", Err: msg, Remote: true})
			continue
		}
		// Leaf cert is first in the chain — match the local one-line-per-file form.
		leaf := certs[0]
		level := "OK"
		switch {
		case leaf.ExpiresIn <= critDays:
			level = "CRIT"
		case leaf.ExpiresIn <= warnDays:
			level = "WARN"
		}
		expiry, _ := time.Parse("2006-01-02", leaf.NotAfter)
		out = append(out, certResult{
			Path:       ep,
			Subject:    leaf.Subject,
			Expiry:     expiry,
			DaysLeft:   leaf.ExpiresIn,
			Level:      level,
			Remote:     true,
			SelfSigned: leaf.IsSelfSigned,
		})
	}
	return out
}

// buildTLSInfo assembles a models.TLSInfo (for --json output) from scan results.
func buildTLSInfo(results []certResult, remotes []string, warnDays int) *models.TLSInfo {
	ti := &models.TLSInfo{RemoteEndpoints: remotes}
	for _, r := range results {
		if r.Err != "" {
			continue
		}
		ci := models.CertInfo{
			Path:         r.Path,
			Subject:      r.Subject,
			ExpiresIn:    r.DaysLeft,
			IsSelfSigned: r.SelfSigned,
		}
		if !r.Expiry.IsZero() {
			ci.NotAfter = r.Expiry.Format("2006-01-02")
		}
		ti.Certs = append(ti.Certs, ci)
		if r.DaysLeft < 0 {
			ti.Expired++
		} else if r.DaysLeft <= warnDays {
			ti.Expiring++
		}
	}
	return ti
}
