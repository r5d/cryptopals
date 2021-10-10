// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// MD4 implementation.
// Reference https://datatracker.ietf.org/doc/html/rfc1320

type Md4 struct {
	hvs    []uint32
	Msg    []byte
	MsgLen int
}

// Initial hash value.
var md4IHashValues []uint32 = []uint32{
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476,
}

func md4F(x, y, z uint32) uint32 {
	return (x & y) | (^x & z)
}

func md4G(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func md4H(x, y, z uint32) uint32 {
	return x ^ y ^ z
}

func md4RoundOneFunc(a, b, c, d, x uint32, s uint) uint32 {
	a = shaAdd(a, md4F(b, c, d), x)
	a = shaRotl(a, s)

	return a
}

func md4RoundTwoFunc(a, b, c, d, x uint32, s uint) uint32 {
	a = shaAdd(a, md4G(b, c, d), x, 0x5A827999)
	a = shaRotl(a, s)

	return a
}

func md4RoundThreeFunc(a, b, c, d, x uint32, s uint) uint32 {
	a = shaAdd(a, md4H(b, c, d), x, 0x6ED9EBA1)
	a = shaRotl(a, s)

	return a
}

func md4Padding(l int) []byte {
	l = l * 8 // msg size in bits

	// Reckon value of `k`
	k := 0
	for ((l + 1 + k) % 512) != 448 {
		k += 1
	}

	// Initialize padding bytes
	pbs := make([]byte, 0)

	// Add bit `1` as byte block.
	pbs = append(pbs, 0x80)
	f := 7 // unclaimed bits in last byte of `pbs`

	// Add `k` bit `0`s
	for i := 0; i < k; i++ {
		if f == 0 {
			pbs = append(pbs, 0x0)
			f = 8
		}
		f = f - 1
	}

	// Add `l` in a 64 bit block in `pbs`
	l64 := uint64(l)
	b64 := make([]byte, 8) // last 64-bits
	for i := 0; i <= 7; i++ {
		// Get 8 last bits.
		b64[i] = byte(l64 & 0xFF)

		// Get rid of the last 8 bits.
		l64 = l64 >> 8
	}
	pbs = append(pbs, b64...)

	return pbs
}

func md4MessageBlocks(pm []byte) [][]uint32 {
	// Break into 512-bit blocks
	bs := BreakIntoBlocks(pm, 64)

	mbs := make([][]uint32, 0) // Message blocks.
	for i := 0; i < len(bs); i++ {
		ws := make([]uint32, 0) // 32-bit words.

		// Break 512-bit (64 bytes) into 32-bit words.
		for j := 0; j < 64; j = j + 4 {
			// Pack 4 bytes into a 32-bit word.
			w := (uint32(bs[i][j]) |
				uint32(bs[i][j+1])<<8 |
				uint32(bs[i][j+2])<<16 |
				uint32(bs[i][j+3])<<24)
			ws = append(ws, w)
		}
		mbs = append(mbs, ws)
	}
	return mbs
}

func (md *Md4) Init(hvs []uint32) {
	// Set Initial Hash Values.
	h := make([]uint32, 4)
	if len(hvs) == 4 {
		copy(h, hvs)
		md.hvs = h
	} else {
		copy(h, md4IHashValues)
		md.hvs = h
	}
}

func (md *Md4) Message(m []byte) {
	md.Msg = m
	md.MsgLen = len(m)
}

// MD4 - Pad message such that its length is a multiple of 512.
func (md *Md4) Pad() []byte {
	// Initialize padded message
	pm := make([]byte, len(md.Msg))
	copy(pm, md.Msg)

	// Add padding.
	pm = append(pm, md4Padding(md.MsgLen)...)

	return pm
}

func (md *Md4) Hash() []byte {
	// Pad message.
	pm := md.Pad()

	// Break into message blocks.
	mbs := md4MessageBlocks(pm)

	// Initialize hash values.
	h := make([]uint32, 4)
	copy(h, md.hvs) // Initial hash values.

	// Process each message block.
	for _, mb := range mbs {

		// Initialize working variables.
		a := h[0]
		b := h[1]
		c := h[2]
		d := h[3]

		//  Round 1.
		a = md4RoundOneFunc(a, b, c, d, mb[0], 3)
		d = md4RoundOneFunc(d, a, b, c, mb[1], 7)
		c = md4RoundOneFunc(c, d, a, b, mb[2], 11)
		b = md4RoundOneFunc(b, c, d, a, mb[3], 19)

		a = md4RoundOneFunc(a, b, c, d, mb[4], 3)
		d = md4RoundOneFunc(d, a, b, c, mb[5], 7)
		c = md4RoundOneFunc(c, d, a, b, mb[6], 11)
		b = md4RoundOneFunc(b, c, d, a, mb[7], 19)

		a = md4RoundOneFunc(a, b, c, d, mb[8], 3)
		d = md4RoundOneFunc(d, a, b, c, mb[9], 7)
		c = md4RoundOneFunc(c, d, a, b, mb[10], 11)
		b = md4RoundOneFunc(b, c, d, a, mb[11], 19)

		a = md4RoundOneFunc(a, b, c, d, mb[12], 3)
		d = md4RoundOneFunc(d, a, b, c, mb[13], 7)
		c = md4RoundOneFunc(c, d, a, b, mb[14], 11)
		b = md4RoundOneFunc(b, c, d, a, mb[15], 19)

		// Round 2
		a = md4RoundTwoFunc(a, b, c, d, mb[0], 3)
		d = md4RoundTwoFunc(d, a, b, c, mb[4], 5)
		c = md4RoundTwoFunc(c, d, a, b, mb[8], 9)
		b = md4RoundTwoFunc(b, c, d, a, mb[12], 13)

		a = md4RoundTwoFunc(a, b, c, d, mb[1], 3)
		d = md4RoundTwoFunc(d, a, b, c, mb[5], 5)
		c = md4RoundTwoFunc(c, d, a, b, mb[9], 9)
		b = md4RoundTwoFunc(b, c, d, a, mb[13], 13)

		a = md4RoundTwoFunc(a, b, c, d, mb[2], 3)
		d = md4RoundTwoFunc(d, a, b, c, mb[6], 5)
		c = md4RoundTwoFunc(c, d, a, b, mb[10], 9)
		b = md4RoundTwoFunc(b, c, d, a, mb[14], 13)

		a = md4RoundTwoFunc(a, b, c, d, mb[3], 3)
		d = md4RoundTwoFunc(d, a, b, c, mb[7], 5)
		c = md4RoundTwoFunc(c, d, a, b, mb[11], 9)
		b = md4RoundTwoFunc(b, c, d, a, mb[15], 13)

		// Round 3
		a = md4RoundThreeFunc(a, b, c, d, mb[0], 3)
		d = md4RoundThreeFunc(d, a, b, c, mb[8], 9)
		c = md4RoundThreeFunc(c, d, a, b, mb[4], 11)
		b = md4RoundThreeFunc(b, c, d, a, mb[12], 15)

		a = md4RoundThreeFunc(a, b, c, d, mb[2], 3)
		d = md4RoundThreeFunc(d, a, b, c, mb[10], 9)
		c = md4RoundThreeFunc(c, d, a, b, mb[6], 11)
		b = md4RoundThreeFunc(b, c, d, a, mb[14], 15)

		a = md4RoundThreeFunc(a, b, c, d, mb[1], 3)
		d = md4RoundThreeFunc(d, a, b, c, mb[9], 9)
		c = md4RoundThreeFunc(c, d, a, b, mb[5], 11)
		b = md4RoundThreeFunc(b, c, d, a, mb[13], 15)

		a = md4RoundThreeFunc(a, b, c, d, mb[3], 3)
		d = md4RoundThreeFunc(d, a, b, c, mb[11], 9)
		c = md4RoundThreeFunc(c, d, a, b, mb[7], 11)
		b = md4RoundThreeFunc(b, c, d, a, mb[15], 15)

		// Compute intermediate hash values.
		h[0] = shaAdd(a, h[0])
		h[1] = shaAdd(b, h[1])
		h[2] = shaAdd(c, h[2])
		h[3] = shaAdd(d, h[3])
	}

	// Slurp md4 digest from hash values.
	d := make([]byte, 0) // md4 digest
	for i := 0; i < 4; i++ {
		// Break 32-bit hash value into 4 bytes.
		hb := make([]byte, 4)
		for j := 0; j <= 3; j++ {
			// Get last 8 bits.
			hb[j] = byte(h[i] & 0xFF)

			// Get rid of last 8 bits.
			h[i] = h[i] >> 8
		}
		d = append(d, hb...)
	}

	return d
}
