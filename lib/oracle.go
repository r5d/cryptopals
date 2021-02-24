// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

var oracleUnknown string = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`

var OracleKey []byte
var OracleIV []byte
var oracleRandom []byte

func init() {
	var err error

	OracleKey, err = RandomKey(16)
	if err != nil {
		panic(err)
	}

	OracleIV, err = RandomKey(16)
	if err != nil {
		panic(err)
	}

	oracleRandom, err = RandomKey(int(RandomInt(1, 4096)))
	if err != nil {
		panic(err)
	}
}

// Given an input `in`, this function AES encrypts `in` using a
// randomly generate 16-byte key using ECB or CBC mode and returns the
// cipher.
func OracleAESRandomEncrypt(in []byte) []byte {
	// Generate random key.
	key, err := RandomKey(16)
	if err != nil {
		panic(err)
	}
	// Generate random initialization vector; needed for AES CBC.
	iv, err := RandomKey(16)
	if err != nil {
		panic(err)
	}

	// Add 5-10 bytes at the beginning and end of `in`
	in = append(randomBytes(5, 10), in...)
	in = append(in, randomBytes(5, 10)...)

	// Randomly encrypt `in` with AES in ECB or CBC mode.
	m := RandomInt(0, 1)
	var out []byte
	if m == 0 {
		// Encrypt with AES in ECB mode.
		out = AESEncryptECB(in, key)
	} else {
		// Encrypt with AES in CBC mode.
		out = AESEncryptCBC(in, key, iv)
	}
	return out
}

func OracleAESEncryptECB(in []byte) []byte {
	return AESEncryptECB(append(in, Base64ToBytes(oracleUnknown)...), OracleKey)
}

func OracleAESVarEncryptECB(in []byte) []byte {
	in = append(oracleRandom, in...)
	in = append(in, Base64ToBytes(oracleUnknown)...)
	return AESEncryptECB(in, OracleKey)
}
