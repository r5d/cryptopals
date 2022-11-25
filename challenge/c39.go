// Copyright © 2022 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C39() {
	rsa, err := lib.RSAGenKey()
	if err != nil {
		fmt.Printf("gen key failed: %v", err)
		return
	}

	msg := []byte("42")
	enc := rsa.Public.Encrypt(msg)
	if len(enc) < 1 {
		fmt.Printf("encrypt failed: %v", enc)
		return
	}
	dec := rsa.Private.Decrypt(enc)
	if !lib.BytesEqual(msg, dec) {
		fmt.Printf("decrypt failed: %v", dec)
		return
	}

	msg = []byte("0x42")
	enc = rsa.Public.Encrypt(msg)
	if len(enc) < 1 {
		fmt.Printf("encrypt failed: %v", enc)
		return
	}
	dec = rsa.Private.Decrypt(enc)
	if !lib.BytesEqual(msg, dec) {
		fmt.Printf("decrypt failed: %v", dec)
		return
	}

	msg = []byte("68f13a29c10617c2c87cccb8db2d40ba05191f75f5a08978e84d829a543fa933")
	enc = rsa.Public.Encrypt(msg)
	if len(enc) < 1 {
		fmt.Printf("encrypt failed: %v", enc)
		return
	}
	dec = rsa.Private.Decrypt(enc)
	if !lib.BytesEqual(msg, dec) {
		fmt.Printf("decrypt failed: %v", dec)
		return
	}
}
