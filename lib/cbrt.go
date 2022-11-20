// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import (
	"math/big"
)

// Cube root tolerance.
var bigCubeRootTolerance = big.NewFloat(0.00001)

// Returns cube root of a.
//
// Uses Newton's method.
// https://en.wikipedia.org/wiki/Newton's_method
func BigCubeRoot(a *big.Float) *big.Float {
	// If x^3 = a, then our f(x) is:
	//     f(x) = x^3 - a
	fx := func(x *big.Float) *big.Float {
		// x^3
		e := big.NewFloat(0)
		e = e.Mul(x, x)
		e = e.Mul(e, x)

		// x^3 - a
		z := big.NewFloat(0).Sub(e, a)

		return z
	}

	// f'(x) is:
	//    f'(x) = 3 * x^2
	fxPrime := func(x *big.Float) *big.Float {
		// x^2
		x2 := big.NewFloat(0).Mul(x, x)

		// 3 * x^2
		z := big.NewFloat(0).Mul(big.NewFloat(3), x2)

		return z
	}

	x0 := a // Initial guess.
	for i := 0; i < 1000000; i++ {
		// f(x0) / f'(x0)
		d := fx(x0)
		d = d.Quo(d, fxPrime(x0))

		// x0 - ( f(x0) / f'(x0) )
		x1 := big.NewFloat(0).Set(x0)
		x1 = x1.Sub(x1, d)

		// x0 - x1
		df := big.NewFloat(0).Set(x0)
		df = df.Sub(df, x1)
		df = df.Abs(df)
		if df.Cmp(bigCubeRootTolerance) == -1 {
			return x1
		}

		x0 = x1
	}
	return nil
}

// Returns cube root of a.
//
// Uses Newton's method.
// https://en.wikipedia.org/wiki/Newton's_method
func BigIntCubeRoot(a *big.Int) *big.Int {
	// If x^3 = a, then our f(x) is:
	//     f(x) = x^3 - a
	fx := func(x *big.Int) *big.Int {
		// x^3
		e := big.NewInt(0)
		e = e.Mul(x, x)
		e = e.Mul(e, x)

		// x^3 - a
		z := big.NewInt(0).Sub(e, a)

		return z
	}

	// f'(x) is:
	//    f'(x) = 3 * x^2
	fxPrime := func(x *big.Int) *big.Int {
		// x^2
		x2 := big.NewInt(0).Mul(x, x)

		// 3 * x^2
		z := big.NewInt(0).Mul(big.NewInt(3), x2)

		return z
	}

	x0 := a // Initial guess.
	zero := big.NewInt(0)
	one := big.NewInt(1)
	for i := 0; i < 1000000; i++ {
		// f(x0) / f'(x0)
		d := fx(x0)
		d = d.Div(d, fxPrime(x0))

		// x0 - ( f(x0) / f'(x0) )
		x1 := big.NewInt(0).Set(x0)
		x1 = x1.Sub(x1, d)

		// x0 - x1
		df := big.NewInt(0).Set(x0)
		df = df.Sub(df, x1)
		df = df.Abs(df)
		if df.Cmp(zero) == 0 {
			return x1.Sub(x1, one)
		}

		x0 = x1
	}
	return nil
}
