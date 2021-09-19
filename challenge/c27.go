// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C27() {
	// Generate random key.
	key, err := lib.RandomBytes(16)
	if err != nil {
		fmt.Printf("Error: %v", err)
		return
	}

	// Make IV same as `key`.
	iv := key

	// Encrypt `plain` with AES-CBC
	encrypt := func(plain []byte) []byte {
		return lib.AESEncryptCBC(plain, key, iv)
	}

	// Same as lib.AESDecryptCBC but ignores padding error and
	// checks if plain text has high ASCII values.
	//
	// Always returns full plain text; even when there is an
	// error.
	decrypt := func(cipher []byte) ([]byte, error) {
		iter := len(cipher) / 16

		lc := iv
		output := make([]byte, 0)
		for i := 0; i < iter; i++ {
			s := (i * 16)
			e := (i * 16) + 16
			c := cipher[s:e]
			output = append(output, lib.FixedXORBytes(
				lib.AESInvCipher(c, key), lc)...)

			lc = c
		}

		// Undo padding
		plain, err := lib.Pkcs7PaddingUndo(output)
		if err != nil {
			// If padding undo fails, just use `output`.
			plain = output
		}

		// Check if `plain` high ASCII
		for _, p := range plain {
			if p >= 128 {
				return plain, lib.CPError{"Has high ASCII values"}
			}
		}

		return plain, nil
	}

	// Encrypt atleast 3 blocks of plain text.
	c := encrypt(lib.StrToBytes(
		"As soon as you are born they make you feel small"))

	// Modify cipher.
	copy(c[32:48], c[0:16])              // C_3 <- C_1
	copy(c[16:32], lib.FillBytes(0, 16)) // C_2 <- 0

	// Try decrypting.
	p, err := decrypt(c)
	if err != nil {
		// Has high ASCII values; recover key.
		k := lib.FixedXORBytes(p[0:16], p[32:48])
		if lib.BytesEqual(k, key) {
			fmt.Printf("Recovered key: %v\n", k)
			return
		}
	}
	fmt.Printf("Could not recover key\n")
}

// Output:
// Recovered key: [62 228 155 158 92 189 217 142 58 118 162 140 165 41 152 237]
