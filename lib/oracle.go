// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import (
	"crypto/rand"
	"math/big"
)

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

// Randomly generates `min` to `max` bytes.
func randomBytes(min, max int64) []byte {
	var rn *big.Int
	var err error
	for {
		rn, err = rand.Int(rand.Reader, big.NewInt(max+1))
		if err != nil {
			panic(err)
		}
		if rn.Int64() >= min {
			break
		}
	}

	bs := make([]byte, rn.Int64())
	_, err = rand.Read(bs)
	if err != nil {
		panic(err)
	}
	return bs
}
