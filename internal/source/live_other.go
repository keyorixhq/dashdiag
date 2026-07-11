//go:build !linux && !darwin

package source

import "errors"

func (l Live) Statfs(_ string) (StatfsInfo, error) {
	return StatfsInfo{}, errors.New("statfs not supported on this platform")
}
