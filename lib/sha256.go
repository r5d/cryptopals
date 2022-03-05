// Copyright © 2022 siddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// SHA-256 implementation.
// Reference https://csrc.nist.gov/publications/detail/fips/180/4/final

type Sha256 struct {
	hvs    []uint32
	Msg    []byte
	MsgLen int
}

// SHA-256 Constants
var sha256K []uint32 = []uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// SHA-256 initial hash values.
var sha256HashValues []uint32 = []uint32{
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
}

// Ch(x,y,z) function.
func sha256FCh(x, y, z uint32) uint32 {
	return (x & y) ^ (^x & z)
}

// Maj(x,y,z) function.
func sha256FMaj(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

// Σ0(x) function.
func sha256FΣ0(x uint32) uint32 {
	return shaRotr(x, 2) ^ shaRotr(x, 13) ^ shaRotr(x, 22)
}

// Σ1(x) function.
func sha256FΣ1(x uint32) uint32 {
	return shaRotr(x, 6) ^ shaRotr(x, 11) ^ shaRotr(x, 25)
}

// σ0(x) function.
func sha256Fσ0(x uint32) uint32 {
	return shaRotr(x, 7) ^ shaRotr(x, 18) ^ shaShr(x, 3)
}

// σ1(x) function.
func sha256Fσ1(x uint32) uint32 {
	return shaRotr(x, 17) ^ shaRotr(x, 19) ^ shaShr(x, 10)
}

// Returns the message schedule W_t for a message block `mb`
// The message schedule has 64 32-bit words.
func sha256MessageSchedule(mb []uint32) []uint32 {
	// Message schedule.
	w := make([]uint32, 0)

	// Generate message schedule.
	for t := 0; t < 64; t++ {
		if t <= 15 {
			w = append(w, mb[t])
		} else {
			w = append(w, shaAdd(
				sha256Fσ1(w[t-2]),
				w[t-7],
				sha256Fσ0(w[t-15]),
				w[t-16],
			))
		}
	}
	return w
}

func (s *Sha256) Init(hvs []uint32) {
	// Set initial hash values.
	h := make([]uint32, 8)
	if len(hvs) == 8 {
		copy(h, hvs)
		s.hvs = h
	} else {
		copy(h, sha256HashValues)
		s.hvs = h
	}
}

func (s *Sha256) Message(m []byte) {
	s.Msg = m
	s.MsgLen = len(m)
}

// SHA-256 - Pad message such that its length is a multiple of 512.
func (s *Sha256) Pad() []byte {
	// Initialize padded message.
	pm := make([]byte, len(s.Msg))
	copy(pm, s.Msg)

	// Add padding.
	pm = append(pm, MDPadding(s.MsgLen)...)

	return pm
}

func (s *Sha256) Hash() []byte {
	// Pad message.
	pm := s.Pad()

	// Break int message blocks.
	mbs := shaMessageBlocks(pm)

	// Initialize hash values.
	hvs := make([]uint32, 8)
	copy(hvs, s.hvs) // Initial hash values.

	// Process each message block.
	for _, mb := range mbs {
		// Get message schedule.
		w := sha256MessageSchedule(mb)

		// Initialize working variables.
		a := hvs[0]
		b := hvs[1]
		c := hvs[2]
		d := hvs[3]
		e := hvs[4]
		f := hvs[5]
		g := hvs[6]
		h := hvs[7]

		for t := 0; t <= 63; t++ {
			t1 := shaAdd(
				h,
				sha256FΣ1(e),
				sha256FCh(e, f, g),
				sha256K[t],
				w[t],
			)
			t2 := shaAdd(sha256FΣ0(a), sha256FMaj(a, b, c))
			h = g
			g = f
			f = e
			e = shaAdd(d, t1)
			d = c
			c = b
			b = a
			a = shaAdd(t1, t2)
		}

		// Compute intermediate hash values.
		hvs[0] = shaAdd(a, hvs[0])
		hvs[1] = shaAdd(b, hvs[1])
		hvs[2] = shaAdd(c, hvs[2])
		hvs[3] = shaAdd(d, hvs[3])
		hvs[4] = shaAdd(e, hvs[4])
		hvs[5] = shaAdd(f, hvs[5])
		hvs[6] = shaAdd(g, hvs[6])
		hvs[7] = shaAdd(h, hvs[7])
	}

	// Slurp sha256 digest from hash values.
	d := make([]byte, 0) // sha256 digest
	for i := 0; i < 8; i++ {
		// Break 32-bit hash value into 4 bytes.
		hb := make([]byte, 4)
		for j := 3; j >= 0; j-- {
			// Get last 8 bits.
			hb[j] = byte(hvs[i] & 0xFF)

			// Get rid of last 8 bits.
			hvs[i] = hvs[i] >> 8
		}
		d = append(d, hb...)
	}

	return d
}
