// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

const b64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func HexToBase64(hex string) string {
	hb := []byte(hex)

	b64 := ""
	for i := 0; i <= len(hb)-3; i = i + 3 {
		a := (HexCharToDec(hb[i])<<8 |
			HexCharToDec(hb[i+1])<<4 |
			HexCharToDec(hb[i+2]))
		b64 += encode(a >> 6)
		b64 += encode(a & 0x3f)
	}
	return b64
}

func encode(b uint16) string {
	return string(b64_table[b])
}

// Strip space and newline characters from string.
func stripSpaceChars(s string) string {
	ss := ""
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			continue
		}
		if s[i] == '\n' {
			continue
		}
		ss += string(s[i])
	}
	return ss
}
