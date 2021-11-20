// Copyright © 2021 siddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C26() {
	key, err := lib.RandomBytes(16)
	if err != nil {
		fmt.Printf("bit flip key: error: %v", err)
	}

	// Generate Nonce for AES counter function.
	nonce := uint64(lib.RandomInt(0, 10))

	quote := func(s string) string {
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
	encrypt := func(s string) []byte {
		in_s := "comment1=cooking%20MCs;userdata="
		in_s += quote(s)
		in_s += ";comment2=%20like%20a%20pound%20of%20bacon"

		c, _ := lib.AESEncryptCTR(lib.StrToBytes(in_s), key,
			lib.AESGenCTRFunc(nonce))
		return c
	}
	decryptHasAdmin := func(c []byte) bool {
		b, _ := lib.AESDecryptCTR(c, key, lib.AESGenCTRFunc(nonce))
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
	// Figure out the byte that translates to target byte `t` for cipher
	// byte `c` assuming the plain text byte at that position is `p`.
	flipByte := func(p, t, c byte) byte {
		io := p ^ c // intermediate output (io) byte
		return t ^ io
	}

	s := ";admin=true"
	c := encrypt(s)
	fmt.Printf("Original Cipher: %v\n", c)

	// Bitflip Attack
	cc := make([]byte, len(c))
	for i := 0; i < len(c)-(16*2)-1; i++ {
		copy(cc, c)

		// Assuming position i is the start of '%3Badmin%3Dtrue'
		cc[i+0] = flipByte('%', 0, c[i+0])          // 0 => NUL
		cc[i+1] = flipByte('3', 0, c[i+1])          // 0 => NUL
		cc[i+2] = flipByte('B', 59, cc[i+2])        // 59 => ;
		cc[i+(8+0)] = flipByte('%', 0, c[i+(8+0)])  // 0 => NUL
		cc[i+(8+1)] = flipByte('3', 0, c[i+(8+1)])  // 0 => NUL
		cc[i+(8+2)] = flipByte('D', 61, c[i+(8+2)]) // 61 => =

		if decryptHasAdmin(cc) {
			fmt.Printf("Modified cipher: %v has ';admin=true;'\n", cc)
			return
		}
	}
	fmt.Printf("Bitflip Attack failed!\n")
}

// Output:
// Original Cipher: [5 199 175 224 49 6 206 218 193 125 227 248 117 41 130 170 129 246 237 4 135 95 67 85 234 222 110 109 26 170 59 138 216 149 142 214 126 176 150 214 86 136 88 52 178 254 5 199 200 5 222 33 61 232 92 13 192 68 67 190 32 138 10 109 91 98 24 142 1 205 17 162 26 23 252 223 249 170 169 170 179 72 111 223 128 238 9 46 35]
// Modified cipher: [5 199 175 224 49 6 206 218 193 125 227 248 117 41 130 170 129 246 237 4 135 95 67 85 234 222 110 109 26 170 59 138 253 166 247 214 126 176 150 214 115 187 33 52 178 254 5 199 200 5 222 33 61 232 92 13 192 68 67 190 32 138 10 109 91 98 24 142 1 205 17 162 26 23 252 223 249 170 169 170 179 72 111 223 128 238 9 46 35] has ';admin=true;'
