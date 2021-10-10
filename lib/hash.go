// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// Converts padded messages bytes `pm` into 512-bit message blocks.
// Each 512-bit block is an array of 16 32-bit words.
// It's assumed bit length of `pm` is a multiple of 512.
func shaMessageBlocks(pm []byte) [][]uint32 {
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

// Returns Merkle–Damgård padding in bytes for length of mesage `l`
// bytes.
func MDPadding(l int) []byte {
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
	for i := 7; i >= 0; i-- {
		// Get 8 last bits.
		b64[i] = byte(l64 & 0xFF)

		// Get rid of the last 8 bits.
		l64 = l64 >> 8
	}
	pbs = append(pbs, b64...)

	return pbs
}
