// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// SHA-1 implementation.
// Reference https://csrc.nist.gov/publications/detail/fips/180/4/final

// Initial hash value.
var sha1IHashValue []uint32 = []uint32{
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476,
	0xc3d2e1f0,
}

// (a + b + ...) mod 2^32
func sha1Add(n ...uint32) uint32 {
	sum := uint64(0)
	for _, v := range n {
		sum += uint64(v)
	}
	return uint32(sum & 0xFFFFFFFF)
}

// Circular Right Shift
func sha1Rotr(x uint32, n uint) uint32 {
	return (x >> n) | (x << (32 - n))
}

// Circular Left Shift
func sha1Rotl(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}

// SHA-1 - Function f_t(x, y, z)
func sha1FT(t int, x, y, z uint32) uint32 {
	switch {
	case t <= 19:
		return (x & y) ^ (^x & z)
	case t >= 20 && t <= 39:
		return x ^ y ^ z
	case t >= 40 && t <= 59:
		return (x & y) ^ (x & z) ^ (y & z)
	case t >= 60 && t <= 79:
		return x ^ y ^ z
	default:
		return uint32(0)
	}
}

// SHA-1 - Constant K_t
func sha1KT(t int) uint32 {
	switch {
	case t <= 19:
		return uint32(0x5a827999)
	case t >= 20 && t <= 39:
		return uint32(0x6ed9eba1)
	case t >= 40 && t <= 59:
		return uint32(0x8f1bbcdc)
	case t >= 60 && t <= 79:
		return uint32(0xca62c1d6)
	default:
		return uint32(0)
	}
}

// SHA-1 - Pad message such that its length is a multiple of 512.
func sha1Pad(m []byte) []byte {
	l := len(m) * 8 // msg size in bits

	// Reckon value of `k`
	k := 0
	for ((l + 1 + k) % 512) != 448 {
		k += 1
	}

	// Initialize padded message
	pm := make([]byte, len(m))
	copy(pm, m)

	// Add bit `1` as byte block.
	pm = append(pm, 0x80)
	f := 7 // unclaimed bits in last byte of `pm`

	// Add `k` bit `0`s
	for i := 0; i < k; i++ {
		if f == 0 {
			pm = append(pm, 0x0)
			f = 8
		}
		f = f - 1
	}

	// Add `l` in a 64 bit block in `pm`
	l64 := uint64(l)
	b64 := make([]byte, 8) // last 64-bits
	for i := 7; i >= 0; i-- {
		// Get 8 last bits.
		b64[i] = byte(l64 & 0xFF)

		// Get rid of the last 8 bits.
		l64 = l64 >> 8
	}
	pm = append(pm, b64...)

	return pm
}

// Converts padded messages bytes `pm` into 512-bit message blocks.
// Each 512-bit block is an array of 16 32-bit words.
func sha1MessageBlocks(pm []byte) [][]uint32 {
	// Break into 512-bit blocks
	bs := BreakIntoBlocks(pm, 64)

	mbs := make([][]uint32, 0) // Message blocks.
	for i := 0; i < len(bs); i++ {
		ws := make([]uint32, 0) // 32-bit words.

		// Break 512-bit (64 bytes) into 32-bit words.
		for j := 0; j < 64; j = j + 4 {
			// Pack 4 bytes into a 32-bit word.
			w := (uint32(bs[i][j])<<24 |
				uint32(bs[i][j+1])<<16 |
				uint32(bs[i][j+2])<<8 |
				uint32(bs[i][j+3]))
			ws = append(ws, w)
		}
		mbs = append(mbs, ws)
	}
	return mbs
}

// Returns the message schedule W_t for message black `mb`
// The message schedule has 80 32-bit words.
func sha1MessageSchedule(mb []uint32) []uint32 {
	// Message schedule.
	w := make([]uint32, 0)

	// Generate message schedule.
	for t := 0; t <= 79; t++ {
		if t <= 15 {
			w = append(w, mb[t])
		} else {
			w = append(w, sha1Rotl(w[t-3]^w[t-8]^w[t-14]^w[t-16], 1))
		}
	}
	return w
}

func Sha1(m []byte) []byte {
	// Pad message.
	pm := sha1Pad(m)

	// Break into message blocks.
	mbs := sha1MessageBlocks(pm)

	// Initialize hash values.
	h := make([]uint32, 5)
	copy(h, sha1IHashValue) // Initial hash values.

	// Process each message block.
	for _, mb := range mbs {
		// Get message schedule.
		w := sha1MessageSchedule(mb)

		// Initialize working variables.
		a := h[0]
		b := h[1]
		c := h[2]
		d := h[3]
		e := h[4]

		for t := 0; t <= 79; t++ {
			tmp := sha1Add(sha1Rotl(a, 5), sha1FT(t, b, c, d),
				e, sha1KT(t), w[t])
			e = d
			d = c
			c = sha1Rotl(b, 30)
			b = a
			a = tmp
		}

		// Compute intermediate hash values.
		h[0] = sha1Add(a, h[0])
		h[1] = sha1Add(b, h[1])
		h[2] = sha1Add(c, h[2])
		h[3] = sha1Add(d, h[3])
		h[4] = sha1Add(e, h[4])
	}

	// Slurp sha1 digest from hash values.
	d := make([]byte, 0) // sha1 digest
	for i := 0; i < 5; i++ {
		// Break 32-bit hash value into 4 bytes.
		hb := make([]byte, 4)
		for j := 3; j >= 0; j-- {
			// Get last 8 bits.
			hb[j] = byte(h[i] & 0xFF)

			// Get rid of last 8 bits.
			h[i] = h[i] >> 8
		}
		d = append(d, hb...)
	}

	return d
}
