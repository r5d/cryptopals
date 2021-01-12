// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import (
	"crypto/rand"
	"math/big"
)

var oracleUnknown string = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`

var oracleKey []byte = make([]byte, 16)

func init() {
	_, err := rand.Read(oracleKey)
	if err != nil {
		panic(err)
	}
}

// Given an input `in`, this function AES encrypts `in` using a
// randomly generate 16-byte key using ECB or CBC mode and returns the
// cipher.
func OracleAESRandomEncrypt(in []byte) []byte {
	// Generate random key.
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	// Generate random initialization vector; needed for AES CBC.
	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	if err != nil {
		panic(err)
	}

	// Add 5-10 bytes at the beginning and end of `in`
	in = append(randomBytes(5, 10), in...)
	in = append(in, randomBytes(5, 10)...)

	// Randomly encrypt `in` with AES in ECB or CBC mode.
	m, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		panic(err)
	}
	var out []byte
	if m.Int64() == 0 {
		// Encrypt with AES in ECB mode.
		out = AESEncryptECB(in, key)
	} else {
		// Encrypt with AES in CBC mode.
		out = AESEncryptCBC(in, key, iv)
	}
	return out
}

func OracleAESEncryptECB(in []byte) []byte {
	return AESEncryptECB(append(in, Base64ToBytes(oracleUnknown)...), oracleKey)
}

// Return a random number from range [min, max]
func randomInt(min, max int64) int64 {
	if min >= max {
		panic("randomInt: min cannot be >= max!")
	}

	var rn *big.Int
	var err error
	for {
		rn, err = rand.Int(rand.Reader, big.NewInt(max+1))
		if err != nil {
			panic(err)
		}
		if rn.Int64() >= min {
			return rn.Int64()
		}
	}
}

// Randomly generates `min` to `max` bytes.
func randomBytes(min, max int64) []byte {
	bs := make([]byte, randomInt(min, max))
	_, err := rand.Read(bs)
	if err != nil {
		panic(err)
	}
	return bs
}
