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

// MT19937 instance struct
type MTRand struct {
	GenSt       [624]uint32
	Index       uint32
	initialized bool
}

var mtLowerMask uint32 = (1 << mtCoefR) - 1
var mtUpperMask uint32 = 0xFFFFFFFF & (^mtLowerMask)

func (r *MTRand) Seed(s uint32) {
	r.Index = mtCoefN
	r.GenSt[0] = s
	for i := uint32(1); i < mtCoefN; i++ {
		r.GenSt[i] = (0xFFFFFFFF &
			(mtF*(r.GenSt[i-1]^(r.GenSt[i-1]>>(mtCoefW-2))) + i))
	}
	r.initialized = true
}

func (r *MTRand) Extract() uint32 {
	if !r.initialized || r.Index >= mtCoefN {
		if !r.initialized {
			r.Seed(5489)
		}
		r.twist()
	}

	y := r.GenSt[r.Index]

	y = y ^ ((y >> mtCoefU) & mtCoefD)
	y = y ^ ((y << mtCoefS) & mtCoefB)
	y = y ^ ((y << mtCoefT) & mtCoefC)
	y = y ^ (y >> mtCoefL)

	r.Index = r.Index + 1

	y = 0xFFFFFFFF & y
	return y
}

func (r *MTRand) twist() {
	for i := uint32(0); i < mtCoefN-1; i++ {
		x := (r.GenSt[i] & mtUpperMask) +
			(r.GenSt[(i+1)%mtCoefN] & mtLowerMask)
		xA := x >> 1
		if x%2 != 0 { // lowest bit of x is 1
			xA = xA ^ mtCoefA
		}
		r.GenSt[i] = r.GenSt[(i+mtCoefM)%mtCoefN] ^ xA
	}
	r.Index = 0
}

func (r *MTRand) UnTemper(y uint32) uint32 {
	y = y ^ (y >> mtCoefL)

	y0 := y
	y = y0 ^ ((y0 << mtCoefT) & mtCoefC)
	y = y0 ^ ((y << mtCoefT) & mtCoefC)

	y0 = y
	y = y0 ^ ((y0 << mtCoefS) & mtCoefB)
	y = y0 ^ ((y << mtCoefS) & mtCoefB)
	y = y0 ^ ((y << mtCoefS) & mtCoefB)
	y = y0 ^ ((y << mtCoefS) & mtCoefB)

	y0 = y
	y = y0 ^ (y0 >> mtCoefU)
	y = y0 ^ (y >> mtCoefU)

	y = 0xFFFFFFFF & y
	return y
}
