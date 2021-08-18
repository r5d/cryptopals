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
	genSt       [624]uint32
	index       uint32
	initialized bool
}

var mtLowerMask uint32 = (1 << mtCoefR) - 1
var mtUpperMask uint32 = 0xFFFFFFFF & (^mtLowerMask)

func (r *MTRand) Seed(s uint32) {
	r.index = mtCoefN
	r.genSt[0] = s
	for i := uint32(1); i < mtCoefN; i++ {
		r.genSt[i] = (0xFFFFFFFF &
			(mtF*(r.genSt[i-1]^(r.genSt[i-1]>>(mtCoefW-2))) + i))
	}
	r.initialized = true
}

func (r *MTRand) Extract() uint32 {
	if !r.initialized || r.index >= mtCoefN {
		if !r.initialized {
			r.Seed(5489)
		}
		r.twist()
	}

	y := r.genSt[r.index]
	y = y ^ ((y >> mtCoefU) & mtCoefD)
	y = y ^ ((y << mtCoefS) & mtCoefB)
	y = y ^ ((y << mtCoefT) & mtCoefC)
	y = y ^ (y >> mtCoefL)

	r.index = r.index + 1

	y = 0xFFFFFFFF & y
	return y
}

func (r *MTRand) twist() {
	for i := uint32(0); i < mtCoefN-1; i++ {
		x := (r.genSt[i] & mtUpperMask) +
			(r.genSt[(i+1)%mtCoefN] & mtLowerMask)
		xA := x >> 1
		if x%2 != 0 { // lowest bit of x is 1
			xA = xA ^ mtCoefA
		}
		r.genSt[i] = r.genSt[(i+mtCoefM)%mtCoefN] ^ xA
	}
	r.index = 0
}
