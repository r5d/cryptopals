// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import (
	"math/big"
	"testing"
)

func TestEGCD(t *testing.T) {
	a := big.NewInt(128)
	b := big.NewInt(96)
	r := egcd(a, b)
	if r.Gcd.Cmp(big.NewInt(32)) != 0 {
		t.Errorf("gcd(128, 96) != 32")
	}
	if r.X.Cmp(big.NewInt(1)) != 0 || r.Y.Cmp(big.NewInt(-1)) != 0 {
		t.Errorf("bézout_coef(128, 96) != {1,-1}")
	}

	a = big.NewInt(360)
	b = big.NewInt(210)
	r = egcd(a, b)
	if r.Gcd.Cmp(big.NewInt(30)) != 0 {
		t.Errorf("gcd(360, 210) != 30")
	}
	if r.X.Cmp(big.NewInt(3)) != 0 || r.Y.Cmp(big.NewInt(-5)) != 0 {
		t.Errorf("bézout_coef(360, 210) != {3,-5}")
	}

	a = big.NewInt(108)
	b = big.NewInt(144)
	r = egcd(a, b)
	if r.Gcd.Cmp(big.NewInt(36)) != 0 {
		t.Errorf("gcd(108, 144) != 36")
	}
	if r.X.Cmp(big.NewInt(-1)) != 0 || r.Y.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("bézout_coef(108, 144) != {-1,1}")
	}

	a = big.NewInt(240)
	b = big.NewInt(46)
	r = egcd(a, b)
	if r.Gcd.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("gcd(240, 46) != 2")
	}
	if r.X.Cmp(big.NewInt(-9)) != 0 || r.Y.Cmp(big.NewInt(47)) != 0 {
		t.Errorf("bézout_coef(240, 46) != {-9,47}")
	}

}

func TestInvMod(t *testing.T) {
	a := big.NewInt(17)
	b := big.NewInt(3120)
	e := big.NewInt(2753) // Expected inverse.
	i, err := invmod(a, b)
	if err != nil {
		t.Errorf("invmod(%v,%v) failed: %v", a, b, err)
		return
	}
	if i.Cmp(e) != 0 {
		t.Errorf("gcd(%v,%v) != %v", a, b, e)
	}

	a = big.NewInt(240)
	b = big.NewInt(47)
	e = big.NewInt(19) // Expected inverse.
	i, err = invmod(a, b)
	if err != nil {
		t.Errorf("invmod(%v,%v) failed: %v", a, b, err)
		return
	}
	if i.Cmp(e) != 0 {
		t.Errorf("gcd(%v,%v) != %v", a, b, e)
	}

	a = big.NewInt(11)
	b = big.NewInt(26)
	e = big.NewInt(19) // Expected inverse.
	i, err = invmod(a, b)
	if err != nil {
		t.Errorf("invmod(%v,%v) failed: %v", a, b, err)
		return
	}
	if i.Cmp(e) != 0 {
		t.Errorf("gcd(%v,%v) != %v", a, b, e)
	}

	a = big.NewInt(3)
	b = big.NewInt(7)
	e = big.NewInt(5) // Expected inverse.
	i, err = invmod(a, b)
	if err != nil {
		t.Errorf("invmod(%v,%v) failed: %v", a, b, err)
		return
	}
	if i.Cmp(e) != 0 {
		t.Errorf("gcd(%v,%v) != %v", a, b, e)
	}
}
