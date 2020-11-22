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

func FillBytes(c byte, l int) []byte {
	if l < 1 {
		return make([]byte, 0)
	}
	bs := make([]byte, l)
	for i := 0; i < l; i++ {
		bs[i] = c
	}
	return bs
}

func StrToBytes(s string) []byte {
	bs := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		bs[i] = byte(s[i])
	}
	return bs
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

func AlphaPunchScore(bs []byte) int {
	s := 0
	for i := 0; i < len(bs); i++ {
		if isAlphaPunch(bs[i]) {
			s += 1
		}
	}
	return s
}

// Returns true if byte 'c' is a non-numeric character in the English language.
func isAlphaPunch(c byte) bool {
	switch {
	case 'A' <= c && c <= 'Z':
		return true
	case 'a' <= c && c <= 'z':
		return true
	case c == ' ' || c == '.':
		return true
	case c == ',' || c == '\'':
		return true
	case c == '"':
		return true
	}
	return false
}
