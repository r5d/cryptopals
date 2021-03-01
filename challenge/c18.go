// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

// Cryptopals #18 - Implement CTR, the stream cipher mode
func C18() {
	// Generates counter function for AES CTR mode.
	genCTRFunc := func(nonce uint64) func() []byte {
		ctr := uint64(0) // Counter
		ff := uint64(0xFF)
		cf := func() []byte {
			cb := make([]byte, 16) // counter block
			var i, j uint
			// Put nonce in the first 8 bytes in cb in little endian format
			for i = 0; i < 8; i++ {
				n := nonce & (ff << (i * 8)) // Reset all except the i^th byte of the nonce
				cb[i] = byte(n >> (i * 8))   // Retrieve i^th byte of the nonce
			}
			// Put counter in the next 8 bytes in cb in little endian format
			for i, j = 8, 0; i < 16; i, j = i+1, j+1 {
				n := ctr & (ff << (j * 8)) // Reset all except the j^th byte of the counter
				cb[i] = byte(n >> (j * 8)) // Retrieve j^th byte of the counter
			}
			ctr += 1 // Increment counter by 1
			return cb
		}
		return cf
	}
	cipher := lib.Base64ToBytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	key := lib.StrToBytes("YELLOW SUBMARINE")
	ctrFunc := genCTRFunc(0)
	plain, err := lib.AESDecryptCTR(cipher, key, ctrFunc)
	if err != nil {
		fmt.Printf("decryption failed: %v", err)
	}
	fmt.Printf("%v\n", lib.BytesToStr(plain))
}

// Output:
// Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby
