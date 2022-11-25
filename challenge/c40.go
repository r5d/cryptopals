// Copyright © 2022 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"
	"math/big"

	"ricketyspace.net/cryptopals/lib"
)

func C40() {
	msg := []byte("42 is the answer.")

	// Generate 3 rsa key pairs and capture the their public keys.
	var rsaPubs []*lib.RSAPub
	for i := 0; i < 3; i++ {
		rsa, err := lib.RSAGenKey()
		if err != nil {
			fmt.Printf("gen key failed: %v", err)
			return
		}
		rsaPubs = append(rsaPubs, rsa.Public)
	}

	// Encrypt message with the 3 rsa public keys.
	var ciphers [][]byte
	for i := 0; i < 3; i++ {
		enc := rsaPubs[i].Encrypt(msg)
		if len(enc) < 1 {
			fmt.Printf("encrypt failed: %v", enc)
			return
		}
		ciphers = append(ciphers, enc)
	}

	// Compute m_s_n
	var msn []*big.Int
	for i := 0; i < 3; i++ {
		msn = append(msn, big.NewInt(0).Mul(
			rsaPubs[(i+1)%3].N(), rsaPubs[(i+2)%3].N(),
		))
	}

	// Compute N_012
	n012 := big.NewInt(1)
	for _, rpub := range rsaPubs {
		n012 = n012.Mul(n012, rpub.N())
	}

	// Compute combination of residues.
	result := big.NewInt(0)
	for i := 0; i < 3; i++ {
		r := big.NewInt(0).Mul(
			big.NewInt(0).SetBytes(ciphers[i]),
			msn[i],
		) // c_i * m_s_i

		// invmod(m_s_i, n_i)
		im, err := lib.InvMod(msn[i], rsaPubs[i].N())
		if err != nil {
			fmt.Printf("invmod: invmod(m_s_%d, n_%d): %v",
				i, i, err,
			)
			return
		}

		// c_i * m_s_i * invmod(m_s_i, n_i)
		r = r.Mul(r, im)

		// Add to result.
		result.Add(result, r)
	}

	// result mod N_012
	result = result.Mod(result, n012)

	// Cube root the result.
	deci := lib.BigIntCubeRoot(result)
	fmt.Printf("Decrypted message: %s\n", deci.Bytes())
}
