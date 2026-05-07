package output

import (
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

func PrintQRCode(url string, mode OutputMode) error {
	if url == "" {
		return nil
	}
	if mode == ModePlain || !isaTTY() {
		fmt.Println("Scan or visit: " + url)
		return nil
	}
	qr, err := qrcode.New(url, qrcode.Medium)
	if err != nil {
		fmt.Println("QR: " + url)
		return nil
	}
	fmt.Println(qr.ToString(false))
	fmt.Println(url)
	return nil
}
