// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

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

func DecToHexChar(i uint16) byte {
	switch {
	case 0 <= i && i <= 9:
		return byte(48 + i)
	case 10 <= i && i <= 15:
		return byte(97 + (i - 10))
	}
	return 0
}

// 'h' must be hex encoded string.
func HexStrToAsciiStr(h string) string {
	a := ""
	lh := len(h)

	if lh < 1 {
		return a
	}
	if lh == 1 {
		return string(HexCharToDec(h[0]))
	}

	for i := 0; i < lh; i += 2 {
		b := HexCharToDec(h[i])<<4 | HexCharToDec(h[i+1])
		a += string(b)
	}
	return a
}

// 'h' must be hex encoded string.
func HexStrToBytes(h string) []byte {
	lh := len(h)

	if lh < 1 {
		return []byte{}
	}
	if lh == 1 {
		return []byte{byte(HexCharToDec(h[0]))}
	}

	bs := make([]byte, 0)
	for i := 0; i < lh; i += 2 {
		b := HexCharToDec(h[i])<<4 | HexCharToDec(h[i+1])
		bs = append(bs, byte(b))
	}
	return bs
}

func AsciiStrToHexStr(as string) string {
	hs := ""
	if len(as) < 1 {
		return hs
	}

	bs := []byte(as)
	for i := 0; i < len(bs); i++ {
		hs += ByteToHexStr(bs[i])
	}
	return hs
}

func ByteToHexStr(b byte) string {
	p := DecToHexChar(uint16(b >> 4))
	q := DecToHexChar(uint16(b & 0xf))

	s := string(p)
	s += string(q)

	return s
}

func BytesToHexStr(bs []byte) string {
	hs := ""

	for i := 0; i < len(bs); i++ {
		hs += ByteToHexStr(bs[i])
	}
	return hs
}

func PrettifyHexStr(hs string) string {
	p_hs := ""
	for i := 0; i < len(hs); i++ {
		p_hs += string(hs[i])

		if (i+1)%32 == 0 {
			p_hs += "\n"
		}
	}
	return p_hs
}
