package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
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
}

type certResult struct {
	Path     string
	Subject  string
	Expiry   time.Time
	DaysLeft int
	Level    string // OK, WARN, CRIT, ERR
	Err      string
}

func runTLS(cmd *cobra.Command, args []string) error {
	warnDays, _ := cmd.Flags().GetInt("warn-days")
	critDays, _ := cmd.Flags().GetInt("crit-days")
	showAll, _ := cmd.Flags().GetBool("all")

	// Collect paths to scan
	paths := args
	if len(paths) == 0 {
		paths = autoDetectCertPaths()
	}

	if len(paths) == 0 {
		fmt.Println("no certificates found — pass paths explicitly or configure ~/.dsd/certs/")
		return nil
	}

	// Scan all paths
	var results []certResult
	for _, p := range paths {
		res := scanCertFile(p, warnDays, critDays)
		results = append(results, res...)
	}

	if len(results) == 0 {
		fmt.Println("no certificates found in scanned paths")
		return nil
	}

	// Sort: CRIT first, then WARN, then OK, then ERR
	order := map[string]int{"CRIT": 0, "WARN": 1, "OK": 2, "ERR": 3}
	sort.Slice(results, func(i, j int) bool {
		if order[results[i].Level] != order[results[j].Level] {
			return order[results[i].Level] < order[results[j].Level]
		}
		return results[i].DaysLeft < results[j].DaysLeft
	})

	// Output
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

		icon := levelIcon(r.Level)
		fmt.Printf("%s  %s\n", icon, r.Path)
		if r.Err != "" {
			fmt.Printf("   error: %s\n", r.Err)
			continue
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
	return nil
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
