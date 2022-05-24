// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"
	"time"

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
	) // Plaintext; last 14 characters is known.
	// Encrypt plaintext.
	cipher := lib.MTXORStream(plain, seed)
	// Try to crack seed
	cseed := crack(cipher)
	if !lib.BytesEqual(cseed, seed) {
		fmt.Printf("Error: %v != %v\n", cseed, seed)
		return
	}
	fmt.Printf("Cracked 16-bit seed %v == %v\n", cseed, seed)

	// Part II: Check if password token is generated using MT19937
	// seeded with current time.
	genPassToken := func(seed uint32, length int) []byte {
		if length < 16 {
			length = 16 // Default length.
		}

		// Init MT19937.
		mtR := new(lib.MTRand)
		mtR.Seed(seed)

		n := uint32(0)
		t := make([]byte, 0) // Token in bytes.
		for i := 0; i < length; i++ {
			if n == uint32(0) {
				n = mtR.Extract()
			}
			t = append(t, byte(n&0xFF)) // Extract last 8 bits.
			n = n >> 8                  // Get rid of the last 8 bits.
		}
		return t
	}
	crackPassToken := func(token []byte) {
		g := uint32(time.Now().Unix())            // Guess
		for g > uint32(time.Now().Unix())-86400 { // Go back 24 hours.
			t := genPassToken(g, len(token))
			if lib.BytesEqual(token, t) {
				fmt.Printf("Token generated using MT19937 seeded"+
					" with %v\n",
					g)
				return
			}
			g -= 1
		}

	}
	crackPassToken(genPassToken(uint32(time.Now().Unix()-lib.RandomInt(60, 86400)), 32))

}

// Output:
// Cracked 16-bit seed [46 80] == [46 80]
// Token generated using MT19937 seeded with 1631200397
