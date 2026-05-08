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
			return status
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
			return status
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
			return status
		}
	}
}

func isaTTY() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func IsPlain(flag bool) bool {
	return flag || !isaTTY()
}
