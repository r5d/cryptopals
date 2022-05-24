// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
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

// Returns a stream function. The stream function returns a random
// byte when invoked.
//
// The `seed` argument must be exactly bytes.
func keystream(seed []byte) func() byte {
	if len(seed) != 2 {
		return nil
	}

	// Pack seed into a uint32
	s := (uint32(seed[0]) << 8) ^ uint32(seed[1])

	// Init MT19937.
	mtR := new(MTRand)
	mtR.Seed(s)

	// Stream func.
	n := uint32(0)
	return func() byte {
		if n == uint32(0) {
			n = mtR.Extract()
		}
		r := byte(n & 0xFF) // Extract last 8 bits.
		n = n >> 8          // Get rid of the last 8 bits.

		return r
	}
}

// XORs `stream` with the MT19937 keystream seeded with `seed`.
func MTXORStream(stream, seed []byte) []byte {
	if len(stream) == 0 {
		return []byte{}
	}
	if len(seed) != 2 {
		return nil
	}

	ks := keystream(seed)
	if ks == nil {
		return nil
	}
	s := make([]byte, 0)
	for i := 0; i < len(stream); i++ {
		s = append(s, stream[i]^ks())
	}
	return s
}
