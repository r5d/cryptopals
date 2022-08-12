// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import (
	"math/big"
)

type GCDResult struct {
	Gcd *big.Int
	X   *big.Int // Bézout coefficient 'x'
	Y   *big.Int // Bézout coefficient 'y'
}

// Copy b to a.
func biCopy(a, b *big.Int) *big.Int {
	a.SetBytes(b.Bytes())
	if b.Sign() == -1 {
		a.Mul(a, big.NewInt(-1))
	}
	return a
}

// Extended Euclidian.
func egcd(a, b *big.Int) GCDResult {
	// Initialize.
	s0 := big.NewInt(1)
	s1 := big.NewInt(0)
	r0 := biCopy(big.NewInt(0), a)
	r1 := biCopy(big.NewInt(0), b)

	for r1.Cmp(big.NewInt(0)) != 0 {
		q := big.NewInt(0)
		q.Div(r0, r1)

		tr := big.NewInt(0)
		tr = tr.Mul(q, r1)
		tr = tr.Sub(r0, tr)

		biCopy(r0, r1)
		biCopy(r1, tr)

		tr = big.NewInt(0)
		tr = tr.Mul(q, s1)
		tr = tr.Sub(s0, tr)

		biCopy(s0, s1)
		biCopy(s1, tr)
	}

	x := biCopy(big.NewInt(0), s0)
	y := big.NewInt(0)
	if b.Cmp(big.NewInt(0)) != 0 {
		y = y.Mul(s0, a)
		y = y.Sub(r0, y)
		y = y.Div(y, b)
	}

	return GCDResult{
		Gcd: biCopy(big.NewInt(0), r0),
		X:   x,
		Y:   y,
	}
}

func invmod(a, n *big.Int) (*big.Int, error) {
	// Initialize.
	t0 := big.NewInt(0)
	t1 := big.NewInt(1)
	r0 := biCopy(big.NewInt(0), n)
	r1 := biCopy(big.NewInt(0), a)

	for r1.Cmp(big.NewInt(0)) != 0 {
		q := big.NewInt(0)
		q.Div(r0, r1)

		tt := big.NewInt(0)
		tt = tt.Mul(q, t1)
		tt = tt.Sub(t0, tt)

		biCopy(t0, t1)
		biCopy(t1, tt)

		tr := big.NewInt(0)
		tr = tr.Mul(q, r1)
		tr = tr.Sub(r0, tr)

		biCopy(r0, r1)
		biCopy(r1, tr)
	}

	if r0.Cmp(big.NewInt(1)) > 0 {
		return nil, CPError{"not invertible"}
	}
	if t0.Cmp(big.NewInt(0)) < 0 {
		t0.Add(t0, n)
	}
	return t0, nil
}
