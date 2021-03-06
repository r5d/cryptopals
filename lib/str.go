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

func BytesToStr(bs []byte) string {
	s := ""
	for i := 0; i < len(bs); i++ {
		s += string(bs[i])
	}
	return s
}

// Strip space and newline characters from string.
func StripSpaceChars(s string) string {
	ss := ""
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			continue
		}
		if s[i] == '\n' {
			continue
		}
		if s[i] == 0 { // NUL character
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

func NumToChar(n int64) byte {
	if 0 <= n && n <= 9 {
		return byte(48 + n)
	}
	return 0
}

func NumToStr(n int64) string {
	s := ""
	for n != 0 {
		s = string(NumToChar(n%10)) + s
		n /= 10
	}
	return s
}

func StrSplitAt(c byte, s string) []string {
	l := make([]string, 0)

	acc := ""
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			l = append(l, acc)
			acc = ""
		} else {
			acc += string(s[i])
		}
	}
	if len(acc) > 0 {
		l = append(l, acc)
	}
	return l
}

func StrToUpper(s string) string {
	us := ""
	for i := 0; i < len(s); i++ {
		us += string(ByteToUpper(s[i]))
	}
	return us
}

func ByteToUpper(b byte) byte {
	if 'a' <= b && b <= 'z' {
		return 'A' + (b - 'a')
	} else {
		return b
	}
}

// Returns true if string 's' has string 'n' in it.
func StrHas(s, n string) bool {
	for i := 0; i < len(s); i++ {
		if s[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
