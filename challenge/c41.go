// Copyright © 2023 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"
	"math/big"

	"ricketyspace.net/cryptopals/lib"
)

func C41() {
	// Generate RSA key pair and setup paraphernalia.
	kpair, err := lib.RSAGenKey()
	if err != nil {
		fmt.Printf("rsa gen key: %v\n", err)
		return
	}
	serverDecrypt := func(cipher []byte) []byte {
		return kpair.Private.Decrypt(cipher)
	}
	pub := kpair.Public

	// N
	N := pub.N()

	// E
	E := pub.E()

	// Message.
	msg := big.NewInt(0).SetBytes([]byte(`{time: 1356304276, social: '555-55-5555'}`))

	// Encrypt.
	c := big.NewInt(0).SetBytes(pub.Encrypt(msg.Bytes()))

	// Decrypt
	if msg.Cmp(big.NewInt(0).SetBytes(serverDecrypt(c.Bytes()))) != 0 {
		fmt.Printf("Decryption failed: %v\n", serverDecrypt(c.Bytes()))
		return
	}

	// S
	rb, err := lib.RandomBytes(1024) // Random bytes.
	if err != nil {
		fmt.Printf("random bytes: %v\n", err)
		return
	}
	S := big.NewInt(0).SetBytes(rb)
	S = S.Mod(S, N)

	// C' = ((S**E mod N) C) mod N
	cp := big.NewInt(0).Exp(S, E, N) // (S**E mod N)
	cp = big.NewInt(0).Mul(cp, c)    // ((S**E mod N) C)
	cp = cp.Mod(cp, N)               // ((S**E mod N) C) mod N => C'

	// P'
	pp := big.NewInt(0).SetBytes(serverDecrypt(cp.Bytes()))

	// Get P from P' => (P'/S mod N)
	sp, err := lib.InvMod(S, N)
	if err != nil {
		fmt.Printf("modinv(S, N) failed")
		return
	}
	plainh := big.NewInt(0).Mul(pp, sp)
	plainh = plainh.Mod(plainh, N)
	if !lib.BytesEqual(plainh.Bytes(), msg.Bytes()) {
		fmt.Printf("Unable to deduce message: %s\n", plainh.Bytes())
		return
	}
	fmt.Printf("Deduced message from ciphertext: %s\n", plainh.Bytes())
}
