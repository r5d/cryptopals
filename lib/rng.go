// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// MT19937 coefficients.
var mtCoefW uint32 = 32
var mtCoefN uint32 = 624
var mtCoefM uint32 = 397
var mtCoefR uint32 = 31
var mtCoefA uint32 = 0x9908B0DF
var mtCoefU uint32 = 11
var mtCoefD uint32 = 0xFFFFFFFF
var mtCoefS uint32 = 7
var mtCoefB uint32 = 0x9D2C5680
var mtCoefT uint32 = 15
var mtCoefC uint32 = 0xEFC60000
var mtCoefL uint32 = 18

var mtF uint32 = 1812433253

// Stores state of MT19937 generator.
var mtGenSt []uint32 = make([]uint32, mtCoefN)
var mtIndex uint32 = mtCoefN + 1

var mtLowerMask uint32 = (1 << mtCoefR) - 1
var mtUpperMask uint32 = 0xFFFFFFFF & (^mtLowerMask)

func MTSeed(seed uint32) {
	mtIndex = mtCoefN
	mtGenSt[0] = seed
	for i := uint32(1); i < mtCoefN; i++ {
		mtGenSt[i] = (0xFFFFFFFF &
			(mtF*(mtGenSt[i-1]^(mtGenSt[i-1]>>(mtCoefW-2))) + i))
	}
}

func MTExtract() uint32 {
	if mtIndex >= mtCoefN {
		if mtIndex > mtCoefN {
			MTSeed(5489)
		}
		mtTwist()
	}

	y := mtGenSt[mtIndex]
	y = y ^ ((y >> mtCoefU) & mtCoefD)
	y = y ^ ((y << mtCoefS) & mtCoefB)
	y = y ^ ((y << mtCoefT) & mtCoefC)
	y = y ^ (y >> mtCoefL)

	mtIndex = mtIndex + 1

	r := 0xFFFFFFFF & y
	return r
}

func mtTwist() {
	for i := uint32(0); i < mtCoefN-1; i++ {
		x := (mtGenSt[i] & mtUpperMask) +
			(mtGenSt[(i+1)%mtCoefN] & mtLowerMask)
		xA := x >> 1
		if x%2 != 0 { // lowest bit of x is 1
			xA = xA ^ mtCoefA
		}
		mtGenSt[i] = mtGenSt[(i+mtCoefM)%mtCoefN] ^ xA
	}
	mtIndex = 0
}
