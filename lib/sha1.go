// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// SHA-1 implementation.
// Reference https://csrc.nist.gov/publications/detail/fips/180/4/final

type Sha1 struct {
	hvs    []uint32
	Msg    []byte
	MsgLen int
}

// Initial hash value.
var sha1IHashValues []uint32 = []uint32{
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476,
	0xc3d2e1f0,
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
			w = append(w, shaRotl(w[t-3]^w[t-8]^w[t-14]^w[t-16], 1))
		}
	}
	return w
}

func (s *Sha1) Init(hvs []uint32) {
	// Set Initial Hash Values.
	h := make([]uint32, 5)
	if len(hvs) == 5 {
		copy(h, hvs)
		s.hvs = h
	} else {
		copy(h, sha1IHashValues)
		s.hvs = h
	}
}

func (s *Sha1) Message(m []byte) {
	s.Msg = m
	s.MsgLen = len(m)
}

// SHA-1 - Pad message such that its length is a multiple of 512.
func (s *Sha1) Pad() []byte {
	// Initialize padded message
	pm := make([]byte, len(s.Msg))
	copy(pm, s.Msg)

	// Add padding.
	pm = append(pm, MDPadding(s.MsgLen)...)

	return pm
}

func (s *Sha1) Hash() []byte {
	// Pad message.
	pm := s.Pad()

	// Break into message blocks.
	mbs := shaMessageBlocks(pm)

	// Initialize hash values.
	h := make([]uint32, 5)
	copy(h, s.hvs) // Initial hash values.

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
			tmp := shaAdd(shaRotl(a, 5), sha1FT(t, b, c, d),
				e, sha1KT(t), w[t])
			e = d
			d = c
			c = shaRotl(b, 30)
			b = a
			a = tmp
		}

		// Compute intermediate hash values.
		h[0] = shaAdd(a, h[0])
		h[1] = shaAdd(b, h[1])
		h[2] = shaAdd(c, h[2])
		h[3] = shaAdd(d, h[3])
		h[4] = shaAdd(e, h[4])
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

func (s *Sha1) Mac(secret, msg []byte) []byte {
	s.Message(append(secret, msg...))
	return s.Hash()
}

func (s *Sha1) MacVerify(secret, msg, mac []byte) bool {
	s.Message(append(secret, msg...))
	if BytesEqual(s.Hash(), mac) {
		return true
	}
	return false
}
