// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import (
	"math/big"
	"testing"
)

func TestBigCubeRoot(t *testing.T) {
	a := big.NewFloat(612)
	acr := BigCubeRoot(a)
	if acr == nil {
		t.Errorf("Could not find cube root of %v\n", a)
		return
	}
	expected := big.NewFloat(8.490184748)
	if big.NewFloat(0).Sub(acr, expected).Cmp(bigCubeRootTolerance) != -1 {
		t.Errorf("Could not find cube root of %v (%v)\n", a, acr)
		return
	}
}

func TestBigIntCubeRoot(t *testing.T) {
	a := big.NewInt(19683)
	acr := BigIntCubeRoot(a)
	if acr == nil {
		t.Errorf("Could not find cube root of %v\n", a)
		return
	}
	expected := big.NewInt(27)
	if big.NewInt(0).Sub(acr, expected).Cmp(big.NewInt(0)) != 0 {
		t.Errorf("Could not find cube root of %v (%v)\n", a, acr)
		return
	}
}
