package output

import "os"

type OutputMode int

const (
	ModeHuman OutputMode = iota
	ModePlain
	ModeReport
	ModeJSON
	ModeYAML
)

func DetectMode(plain, report bool, outputFmt string) OutputMode {
	switch {
	case outputFmt == "json":
		return ModeJSON
	case outputFmt == "yaml":
		return ModeYAML
	case outputFmt == "quiet":
		return ModePlain
	case report:
		return ModeReport
	case plain:
		return ModePlain
	case !isaTTY():
		return ModePlain
	default:
		return ModeHuman
	}
}

// StatusIcon enforces its own allowlist of known status tokens — every
// current caller happens to pre-map an Insight.Level to one of these before
// calling in, but that invariant lives entirely outside this function. Rather
// than echo an arbitrary/unrecognized status string verbatim (a defense-in-
// depth gap: a future caller sourcing status from a capture/config file
// without pre-validating it could otherwise inject terminal escape sequences
// via the default branch), fall back to a fixed "UNKNOWN" token.
func StatusIcon(status string, mode OutputMode) string {
	switch mode {
	case ModePlain, ModeJSON, ModeYAML:
		switch status {
		case "ok":
			return "OK"
		case "warn":
			return "WARN"
		case "fail":
			return "CRIT"
		case "info":
			return "INFO"
		case "pending":
			return "PENDING"
		default:
			return "UNKNOWN"
		}
	case ModeReport:
		switch status {
		case "ok":
			return "✅ OK"
		case "warn":
			return "⚠️  WARN"
		case "fail":
			return "❌ FAIL"
		case "info":
			return "ℹ️  INFO"
		case "pending":
			return "⏳ PENDING"
		default:
			return "❓ UNKNOWN"
		}
	default: // ModeHuman
		switch status {
		case "ok":
			return "✅"
		case "warn":
			return "⚠️"
		case "fail":
			return "❌"
		case "info":
			return "ℹ️"
		case "pending":
			return "⏳"
		default:
			return "❓"
		}
	}
}

// isaTTY is a seam so tests can simulate a TTY session without depending on
// the real stderr of the test process (which is never a character device
// under go test).
var isaTTY = func() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func IsPlain(flag bool) bool {
	return flag || !isaTTY()
}
