// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import "math/big"

type DH struct {
	p  *big.Int
	g  *big.Int
	pk *big.Int // Private key
}

func NewDH(ps, gs string) (*DH, bool) {
	p, ok := new(big.Int).SetString(StripSpaceChars(ps), 16)
	if !ok {
		return nil, false
	}
	g, ok := new(big.Int).SetString(StripSpaceChars(gs), 16)
	if !ok {
		return nil, false
	}

	// Init DH.
	dh := new(DH)
	dh.p = p
	dh.g = g
	dh.pk = big.NewInt(RandomInt(1, 10000000))
	return dh, true
}

// Return our public key.
func (dh *DH) Pub() *big.Int {
	return new(big.Int).Exp(dh.g, dh.pk, dh.p)
}

// Return shared secret between us and the other party.
// `pub` is the other party's public key.
func (dh *DH) SharedSecret(pub *big.Int) *big.Int {
	return new(big.Int).Exp(pub, dh.pk, dh.p)
}
