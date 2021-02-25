// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

var oracleUnknown string = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`

var oracleKey []byte
var oracleRandom []byte

func init() {
	var err error

	oracleKey, err = RandomBytes(16)
	if err != nil {
		panic(err)
	}

	oracleRandom, err = RandomBytes(int(RandomInt(1, 4096)))
	if err != nil {
		panic(err)
	}
}

func OracleAESEncryptECB(in []byte) []byte {
	return AESEncryptECB(append(in, Base64ToBytes(oracleUnknown)...), oracleKey)
}

func OracleAESVarEncryptECB(in []byte) []byte {
	in = append(oracleRandom, in...)
	in = append(in, Base64ToBytes(oracleUnknown)...)
	return AESEncryptECB(in, oracleKey)
}
