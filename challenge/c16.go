// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"crypto/rand"
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C16() {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		fmt.Printf("bit flip key: error: %v", err)
	}
	iv := make([]byte, 16)
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

		return lib.AESEncryptCBC(lib.StrToBytes(in_s), key,
			iv)
	}
	decryptHasAdmin := func(c []byte) bool {
		b, _ := lib.AESDecryptCBC(c, key, iv)
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
// Original Cipher: [18 227 203 76 201 225 61 211 210 75 210 131 101 134 52 68 63 93 34 217 140 103 69 179 175 140 243 88 200 210 29 153 225 201 56 174 159 246 159 32 75 234 203 115 144 56 108 102 60 215 232 204 192 90 54 80 81 119 202 171 27 117 58 102 5 54 72 102 149 132 143 17 198 127 164 117 41 211 56 142 114 185 200 68 33 239 39 188 38 22 14 108 226 223 158 221]
// Modified cipher: [18 227 203 76 201 225 61 211 210 75 210 131 101 134 52 68 26 110 91 217 140 103 69 179 138 191 138 88 200 210 29 153 225 201 56 174 159 246 159 32 75 234 203 115 144 56 108 102 60 215 232 204 192 90 54 80 81 119 202 171 27 117 58 102 5 54 72 102 149 132 143 17 198 127 164 117 41 211 56 142 114 185 200 68 33 239 39 188 38 22 14 108 226 223 158 221] has ';admin=true;'
