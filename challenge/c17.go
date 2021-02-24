// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

// Cryptopals #17 - CBC padding oracle attack
func C17() {
	key, err := lib.RandomKey(16)
	if err != nil {
		fmt.Printf("key generation: error: %v\n", err)
	}
	cookies := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}
	encrypt := func() ([]byte, []byte) {
		r := lib.RandomInt(0, int64(len(cookies)-1))
		p := lib.Base64ToBytes(cookies[r])
		k := key
		iv, err := lib.RandomKey(16)
		if err != nil {
			fmt.Printf("iv generation: error: %v\n", err)
		}
		c := lib.AESEncryptCBC(p, k, iv)

		return c, iv
	}
	decrypt := func(c, iv []byte) bool {
		k := key
		_, err := lib.AESDecryptCBC(c, k, iv)
		if err != nil {
			return false
		}
		return true
	}
	setKnownBytes := func(ivc, pb []byte, pd byte, d int) []byte {
		for i := d + 1; i < 16; i++ {
			io := ivc[i] ^ pb[i] // Get intermediate output
			id := io ^ pd        // iv' at position i
			ivc[i] = id
		}
		return ivc
	}
	inMap := func(pm map[int][]byte, d int, pg byte) bool {
		for _, p := range pm[d] {
			if p == pg {
				return true
			}
		}
		return false
	}
	decryptBlock := func(cb, iv []byte) []byte {
		pb := make([]byte, 16)        // Plaintext block
		d := 15                       // Represents the current byte position getting decrypted.
		pm := make(map[int][]byte, 0) // Plain text guesses at position d

		for d >= 0 { // An iteration decrypts the d^th byte position
			pd := byte(16 - d) // Padding character

			// Init guesses at positon 'd' array in pm map.
			if _, ok := pm[d]; !ok {
				pm[d] = make([]byte, 0)
			}

			found := false // Set when decrypt works on a modified iv'
			for i := 255; i >= 0; i-- {
				pg := byte(i)    // Guess byte at d^th position
				io := iv[d] ^ pg // Get intermediate output
				id := io ^ pd    // iv' at position d

				// Make fresh copy of iv
				ivc := make([]byte, 16)
				copy(ivc, iv)

				// Set appropriate bytes from d+1 .. 15
				ivc = setKnownBytes(ivc, pb, pd, d)

				// Mody d^th character of ivc to id
				ivc[d] = id

				if decrypt(cb, ivc) {
					// (Possible) Plain text byte
					// at position d found. Check
					// if this was guessed before.
					if inMap(pm, d, pg) {
						// Guess was already
						// found; so ignore
						// this.
						continue
					}
					// Add to guess list.
					pm[d] = append(pm[d], pg)

					pb[d] = pg
					found = true
					break
				}
			}
			if found {
				d -= 1
			} else {
				// Our guess at d+1 is incorrect; backtrack.
				d += 1
			}
		}
		return pb
	}
	attack := func(c, iv []byte) []byte {
		n := len(c) / 16     // Number of cipher blocks
		p := make([]byte, 0) // Plaintext
		for i := 0; i < n; i++ {
			// Decrypt i^th block
			s := i * 16
			e := s + 16
			pb := decryptBlock(c[s:e], iv)
			p = append(p, pb...) // Append i^th plaintext block

			// Current cipher block becomes the
			// initialization vector for decrypting the
			// next cipher block.
			iv = c[s:e]
		}
		return p
	}
	c, iv := encrypt()
	p := attack(c, iv)
	p, e := lib.Pkcs7PaddingUndo(p)
	if e != nil {
		panic("plaintext padding undo failed!")
	}
	fmt.Printf("%s\n", lib.BytesToStr(p))
}

// Output
// $ while true; do
// > ./cryptopals -c 17
// > done
// 000001With the bass kicked in and the Vega's are pumpin'
// 000001With the bass kicked in and the Vega's are pumpin'
// 000009ith my rag-top down so my hair can blow
// 000008ollin' in my five point oh
// 000008ollin' in my five point oh
// 000000Now that the party is jumping
// 000009ith my rag-top down so my hair can blow
// 000008ollin' in my five point oh
// 000003Cooking MC's like a pound of bacon
// 000001With the bass kicked in and the Vega's are pumpin'
// 000009ith my rag-top down so my hair can blow
// 000002Quick to the point, to the point, no faking
// 000008ollin' in my five point oh
// 000002Quick to the point, to the point, no faking
// 000002Quick to the point, to the point, no faking
// 000003Cooking MC's like a pound of bacon
// 000005I go crazy when I hear a cymbal
// 000003Cooking MC's like a pound of bacon
// 000002Quick to the point, to the point, no faking
// 000001With the bass kicked in and the Vega's are pumpin'
// 000006And a high hat with a souped up tempo
// 000000Now that the party is jumping
// 000000Now that the party is jumping
// 000008ollin' in my five point oh
// 000003Cooking MC's like a pound of bacon
// 000000Now that the party is jumping
// 000006And a high hat with a souped up tempo
// 000006And a high hat with a souped up tempo
// 000006And a high hat with a souped up tempo
// 000007I'm on a roll, it's time to go solo
// 000006And a high hat with a souped up tempo
// 000004Burning 'em, if you ain't quick and nimble
// 000009ith my rag-top down so my hair can blow
// 000008ollin' in my five point oh
// 000006And a high hat with a souped up tempo
// 000007I'm on a roll, it's time to go solo
// 000001With the bass kicked in and the Vega's are pumpin'
// 000006And a high hat with a souped up tempo
// 000006And a high hat with a souped up tempo
// 000009ith my rag-top down so my hair can blow
// ^C
