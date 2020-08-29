// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package enc

// Adapted from
// https://go.googlesource.com/go/+/refs/tags/go1.15/src/encoding/hex/hex.go#83
func HexCharToDec(c byte) uint16 {
	switch {
	case '0' <= c && c <= '9':
		return uint16(c - '0')
	case 'a' <= c && c <= 'f':
		return uint16(c - 'a' + 10)
	}
	return 0
}
