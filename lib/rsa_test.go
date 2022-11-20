// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import (
	"math/big"
	"testing"
)

func TestInvMod(t *testing.T) {
	a := big.NewInt(17)
	b := big.NewInt(3120)
	e := big.NewInt(2753) // Expected inverse.
	i, err := InvMod(a, b)
	if err != nil {
		t.Errorf("InvMod(%v,%v) failed: %v", a, b, err)
		return
	}
	if i.Cmp(e) != 0 {
		t.Errorf("gcd(%v,%v) != %v", a, b, e)
	}

	a = big.NewInt(240)
	b = big.NewInt(47)
	e = big.NewInt(19) // Expected inverse.
	i, err = InvMod(a, b)
	if err != nil {
		t.Errorf("InvMod(%v,%v) failed: %v", a, b, err)
		return
	}
	if i.Cmp(e) != 0 {
		t.Errorf("gcd(%v,%v) != %v", a, b, e)
	}

	a = big.NewInt(11)
	b = big.NewInt(26)
	e = big.NewInt(19) // Expected inverse.
	i, err = InvMod(a, b)
	if err != nil {
		t.Errorf("InvMod(%v,%v) failed: %v", a, b, err)
		return
	}
	if i.Cmp(e) != 0 {
		t.Errorf("gcd(%v,%v) != %v", a, b, e)
	}

	a = big.NewInt(3)
	b = big.NewInt(7)
	e = big.NewInt(5) // Expected inverse.
	i, err = InvMod(a, b)
	if err != nil {
		t.Errorf("InvMod(%v,%v) failed: %v", a, b, err)
		return
	}
	if i.Cmp(e) != 0 {
		t.Errorf("gcd(%v,%v) != %v", a, b, e)
	}
}

func TestRSAGenKey(t *testing.T) {
	pair, err := RSAGenKey()
	if err != nil {
		t.Errorf("genkey: %v", err)
		return
	}
	if pair.Public == nil {
		t.Error("genkey: pub key is nil")
		return
	}
	if pair.Public.e.Cmp(big.NewInt(0)) < 1 {
		t.Error("genkey: e is invalid")
		return
	}
	if pair.Public.n.Cmp(big.NewInt(0)) < 1 {
		t.Error("genkey: n is invalid")
		return
	}
	if pair.Private == nil {
		t.Error("genkey: private key is nil")
		return
	}
	if pair.Private.d.Cmp(big.NewInt(0)) < 1 {
		t.Error("genkey: d is invalid")
		return
	}
	if pair.Private.n.Cmp(big.NewInt(0)) < 1 {
		t.Error("genkey: n is invalid")
		return
	}
	if pair.Public.n.Cmp(pair.Private.n) != 0 {
		t.Error("genkey: public.n != private.n")
		return
	}
}

func TestRSAEncryptDecrypt(t *testing.T) {
	pair, err := RSAGenKey()
	if err != nil {
		t.Errorf("genkey: %v", err)
		return
	}
	pub := pair.Public
	prv := pair.Private

	// [1] Encrypt.
	msg := []byte("42")
	enc := pub.Encrypt(msg)
	if len(enc) < 1 {
		t.Errorf("encrypt failed: %v", enc)
		return
	}
	// [1] Decrypt.
	dec := prv.Decrypt(enc)
	if !BytesEqual(msg, dec) {
		t.Errorf("decrypt failed: %v", dec)
		return
	}

	// [2] Encrypt.
	msg = []byte("0xd1a4a6e870b40a261827f17741c19facf80d01a537d55e59abe5d615d961a23f")
	enc = pub.Encrypt(msg)
	if len(enc) < 1 {
		t.Errorf("encrypt failed: %v", enc)
		return
	}
	// [2] Decrypt.
	dec = prv.Decrypt(enc)
	if !BytesEqual(msg, dec) {
		t.Errorf("decrypt failed: %v", dec)
		return
	}
}
