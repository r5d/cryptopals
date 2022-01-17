// Copyright © 2021 siddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// Key: ASCII character; Value: score
var AsciiScores map[byte]int = make(map[byte]int, 0)

// Printable ASCII characters orrdered by frequency.
// (https://mdickens.me/typing/letter_frequency.html)
var PrintableAscii []byte = []byte{
	' ', 'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd',
	'c', 'u', 'm', 'f', 'g', 'p', 'y', 'w', 'b', ',', '.',
	'v', 'k', '-', '"', '_', '\'', 'x', ')', '(', ';', '0', 'j',
	'1', 'q', '=', '2', ':', 'z', '/', '*', '!', '?', '$', '3',
	'5', '>', '{', '}', '4', '9', '[', ']', '8', '6', '7', '\\',
	'+', '|', '&', '<', '%', '@', '#', '^', '`', '~',
}

func init() {
	// Initialize AsciiScores
	for pos, a := range PrintableAscii {
		AsciiScores[a] = 255 - pos
		// Also add the uppercase version of ascii
		// character if it exists.
		au := ByteToUpper(a)
		if a != au {
			AsciiScores[au] = 255 - pos
		}
	}
}

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
		s += AsciiScores[bs[i]]
	}
	return s
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

// Converts a string to an integer.
func StrToNum(s string) (int, error) {
	var negative bool
	var n int

	if len(s) < 1 {
		return 0, CPError{"invalid number"}
	}
	if s[0] == '-' {
		negative = true
		s = s[1:]
	}
	u := 1
	for i := len(s) - 1; i >= 0; i-- {
		b := s[i]
		if b >= '0' && b <= '9' {
			n += int(b-48) * u
			u *= 10
		} else {
			return 0, CPError{"invalid number"}
		}
	}
	if negative {
		n *= -1
	}
	return n, nil
}
