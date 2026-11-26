package output

import (
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

func PrintQRCode(url string, mode OutputMode) error {
	// url may originate from a network response (a share-link server) once
	// --share is wired up — strip control/ANSI-escape bytes before it can
	// reach the terminal verbatim. Sanitize before the empty check so an
	// all-control-character URL prints nothing, not a dangling "QR: " line.
	url = SanitizeControl(url)
	if url == "" {
		return nil
	}
	// stdout must stay a pure structured-output stream in JSON/YAML mode —
	// never mix in URL text or QR block-art, even if stdout happens to be a
	// TTY (an operator running `dsd health --json --share` interactively).
	if mode == ModeJSON || mode == ModeYAML {
		return nil
	}
	if mode == ModePlain || !isaTTY() {
		fmt.Println("Scan or visit: " + url)
		return nil
	}
	qr, err := qrcode.New(url, qrcode.Medium)
	if err != nil {
		fmt.Println("QR: " + url)
		return nil //nolint:nilerr // QR rendering is decoration; the share URL itself is printed on the line above, so nothing is lost
	}
	fmt.Println(qr.ToString(false))
	fmt.Println(url)
	return nil
}
