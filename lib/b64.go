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

func Base64ToBytes(enc string) []byte {
	enc = StripSpaceChars(enc)

	l := len(enc)
	bs := make([]byte, 3*(l/4))

	// Base64 decode.
	for i, j := 0, 0; i <= l-4; i, j = i+4, j+3 {
		// Jam 24 bits together.
		a := index(enc[i])<<18 |
			index(enc[i+1])<<12 |
			index(enc[i+2])<<6 |
			index(enc[i+3])

		// Get first byte.
		bs[j] = byte(a >> 16)

		if enc[i+2] == '=' {
			return bs[0 : j+1]
		}
		// Get second byte.
		bs[j+1] = byte((a & 0xff00) >> 8)

		if enc[i+3] == '=' {
			return bs[0 : j+2]
		}
		// Get third byte.
		bs[j+2] = byte(a & 0xff)
	}
	return bs
}

func encode(b uint16) string {
	return string(b64_table[b])
}

// Return the index for a base64 character.
func index(c byte) uint32 {
	for i := 0; i < 64; i++ {
		if c == b64_table[i] {
			return uint32(i)
		}
	}
	return uint32(0)
}
