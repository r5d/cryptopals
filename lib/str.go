// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

func FillStr(a string, l int) string {
	b := ""
	if l < 1 {
		return b
	}
	for i := 0; i < l; i++ {
		b += a
	}
	return b
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

func AlphaScore(bs []byte) int {
	s := 0
	for i := 0; i < len(bs); i++ {
		if isAlpha(bs[i]) {
			s += 1
		}
	}
	return s
}

func isAlpha(c byte) bool {
	switch {
	case 'A' <= c && c <= 'Z':
		return true
	case 'a' <= c && c <= 'z':
		return true
	}
	return false
}
