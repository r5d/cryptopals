// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"crypto/rand"
	"fmt"
	"ricketyspace.net/cryptopals/lib"
)

var cbcBitFlipKey []byte = make([]byte, 16)
var cbcBitFlipIV []byte = make([]byte, 16)

func init() {
	_, err := rand.Read(cbcBitFlipKey)
	if err != nil {
		panic(err)
	}

	// Initialization vector for CBC encryption.
	for i := 0; i < len(cbcBitFlipIV); i++ {
		cbcBitFlipIV[i] = '0'
	}
}

func C16() {
	s := ";admin=true"
	c := cbcBitFlipEncrypt(s)
	d := lib.AESDecryptCBC(c, cbcBitFlipKey, cbcBitFlipIV)
	fmt.Printf("Cipher for '%v': %v\n", s, c)
	fmt.Printf("Cipher decrypts to: %v == '%v'\n", d, lib.BytesToStr(d))

	// Bitflip Attack
	cc := make([]byte, len(c))
	for i := 0; i < len(c)-(16*2)-1; i++ {
		copy(cc, c)

		cc[i+0] = cbcGetFlipByte(i, 0, c)
		cc[i+1] = cbcGetFlipByte(i+1, 0, c)
		cc[i+2] = cbcGetFlipByte(i+2, 59, c)
		cc[i+(8+0)] = cbcGetFlipByte(i+(8+0), 0, c)
		cc[i+(8+1)] = cbcGetFlipByte(i+(8+1), 0, c)
		cc[i+(8+2)] = cbcGetFlipByte(i+(8+2), 61, c)

		if cbcBitFlipDecryptHasAdmin(cc) {
			dc := lib.AESDecryptCBC(cc, cbcBitFlipKey, cbcBitFlipIV)
			fmt.Printf("Modified cipher: %v\n", cc)
			fmt.Printf("Modified cipher decrypts to: %v == '%v'\n", dc, lib.BytesToStr(dc))
			return
		}
	}
	fmt.Printf("Bitflip Attack failed!\n")
}

func cbcBitFlipEncrypt(s string) []byte {
	in_s := "comment1=cooking%20MCs;userdata="
	in_s += cbcBitFlipQuote(s)
	in_s += ";comment2=%20like%20a%20pound%20of%20bacon"

	return lib.AESEncryptCBC(lib.StrToBytes(in_s), cbcBitFlipKey,
		cbcBitFlipIV)
}

func cbcBitFlipDecryptHasAdmin(c []byte) bool {
	b := lib.AESDecryptCBC(c, cbcBitFlipKey, cbcBitFlipIV)
	s := lib.BytesToStr(b)

	// Convert to a map
	m := make(map[string]string, 0)
	for _, r := range lib.StrSplitAt(';', s) {
		kv := lib.StrSplitAt('=', r)
		if len(kv) != 2 {
			continue // ignore
		}
		kv[0] = lib.StripSpaceChars(kv[0])
		kv[1] = lib.StripSpaceChars(kv[1])
		m[kv[0]] = kv[1]
	}
	if _, ok := m["admin"]; ok && lib.StrHas(m["admin"], "true") {
		return true
	}
	return false
}

func cbcBitFlipQuote(s string) string {
	qs := ""
	for i := 0; i < len(s); i++ {
		if s[i] == ';' || s[i] == '=' {
			qs += "%" + lib.StrToUpper(lib.ByteToHexStr(s[i]))
		} else {
			qs += string(s[i])
		}
	}
	return qs
}

// Figure out the byte that translates to target byte `t` at position
// `p+16` in the cipher `c`.
func cbcGetFlipByte(p int, t byte, c []byte) byte {
	cc := make([]byte, len(c))
	copy(cc, c)

	for i := 0; i < 256; i++ {
		// Flip a byte in the cipher.
		cc[p] = byte(i)

		dc := lib.AESDecryptCBC(cc, cbcBitFlipKey, cbcBitFlipIV)
		if dc[p+16] == t {
			return byte(i)
		}
	}
	panic("flip byte not found!")
}

// Output:
// Cipher for ';admin=true': [255 28 49 204 17 8 217 219 157 134 137 122 183 114 228 2 102 21 1 101 7 150 7 113 217 139 168 112 72 208 228 10 99 124 250 204 142 192 141 237 142 100 131 14 3 99 112 3 48 141 173 245 1 130 222 110 237 114 248 141 145 118 239 14 231 52 125 140 58 233 128 228 58 195 107 141 196 39 108 5 130 119 120 91 71 66 161 37 172 158 196 5 67 226 35 137]
// Cipher decrypts to: [99 111 109 109 101 110 116 49 61 99 111 111 107 105 110 103 37 50 48 77 67 115 59 117 115 101 114 100 97 116 97 61 37 51 66 97 100 109 105 110 37 51 68 116 114 117 101 59 99 111 109 109 101 110 116 50 61 37 50 48 108 105 107 101 37 50 48 97 37 50 48 112 111 117 110 100 37 50 48 111 102 37 50 48 98 97 99 111 110] == 'comment1=cooking%20MCs;userdata=%3Badmin%3Dtrue;comment2=%20like%20a%20pound%20of%20bacon'
// Modified cipher: [255 28 49 204 17 8 217 219 157 134 137 122 183 114 228 2 67 38 120 101 7 150 7 113 252 184 209 112 72 208 228 10 99 124 250 204 142 192 141 237 142 100 131 14 3 99 112 3 48 141 173 245 1 130 222 110 237 114 248 141 145 118 239 14 231 52 125 140 58 233 128 228 58 195 107 141 196 39 108 5 130 119 120 91 71 66 161 37 172 158 196 5 67 226 35 137]
// Modified cipher decrypts to: [99 111 109 109 101 110 116 49 61 99 111 111 107 105 110 103 39 147 68 128 41 248 225 42 92 25 53 219 59 222 53 100 0 0 59 97 100 109 105 110 0 0 61 116 114 117 101 59 99 111 109 109 101 110 116 50 61 37 50 48 108 105 107 101 37 50 48 97 37 50 48 112 111 117 110 100 37 50 48 111 102 37 50 48 98 97 99 111 110] == 'comment1=cooking'D)øá*\5Û;Þ5d;admin=true;comment2=%20like%20a%20pound%20of%20bacon'
