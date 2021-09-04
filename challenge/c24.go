// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C24() {
	// Part I: Crack MT19937 16-bit seed.
	crack := func(stream []byte) []byte {
		i, j := byte(0), byte(0)
		for i <= 255 {
			gs, m := lib.MTXORStream(stream, []byte{i, j}), true
			for k := len(gs) - 1; k >= len(gs)-14; k-- {
				if gs[k] != 'A' {
					m = false
				}
			}
			if m {
				return []byte{i, j}
			}
			j += 1
			if j == 0 {
				i += 1
			}
		}
		return []byte{}
	}
	seed, err := lib.RandomBytes(2) // Generate random seed.
	if err != nil {
		panic(err)
	}
	plain := append(
		lib.RandomBytesWithLengthBetween(8, 64),
		lib.StrToBytes("AAAAAAAAAAAAAA")..., // 14 'A's.
	) // Plaintext; last 14 characters known.
	cipher := lib.MTXORStream(plain, seed) // Encrypt plaintext.
	cseed := crack(cipher)                 // Try to crack seed
	if lib.BytesEqual(cseed, seed) {
		panic(fmt.Errorf("Unable to crack 16-bit seed %v != %v\n", cseed, seed))
	}
	fmt.Printf("Cracked 16-bit seed %v == %v\n", cseed, seed)
}

// Output:
// Cracked 16-bit seed [74 8] == [74 8]
