// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package enc

const b64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func HexToBase64(hex string) string {
	hb := []byte(hex)

	b64 := ""
	for i := 0; i <= len(hb)-3; i = i + 3 {
		a := (fromHexChar(hb[i])<<8 |
			fromHexChar(hb[i+1])<<4 |
			fromHexChar(hb[i+2]))
		b64 += encode(a >> 6)
		b64 += encode(a & 0b111111)
	}
	return b64
}

func encode(b uint16) string {
	return string(b64_table[b])
}

// Adapted from
// https://go.googlesource.com/go/+/refs/tags/go1.15/src/encoding/hex/hex.go#83
func fromHexChar(c byte) uint16 {
	switch {
	case '0' <= c && c <= '9':
		return uint16(c - '0')
	case 'a' <= c && c <= 'f':
		return uint16(c - 'a' + 10)
	}
	return 0
}
