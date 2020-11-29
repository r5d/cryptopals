// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// Breaks 'cb' into blocks of 'keysize'
func BreakIntoBlocks(cb []byte, keysize int) [][]byte {
	if len(cb) < 1 {
		return make([][]byte, 0)
	}

	// Compute the number of blocks.
	nb := len(cb) / keysize
	if len(cb)%keysize != 0 {
		nb += 1
	}
	blocks := make([][]byte, nb)

	for i, j, k := 0, 0, 0; i < len(cb); i++ {
		if len(blocks[k]) == 0 {
			blocks[k] = make([]byte, keysize)
		}
		blocks[k][j] = cb[i]

		j += 1
		if j == keysize {
			j = 0
			k += 1
		}
	}
	return blocks
}

func TransposeBlocks(blocks [][]byte, keysize int) [][]byte {
	if len(blocks) < 1 {
		return make([][]byte, 0)
	}

	tblocks := make([][]byte, keysize)
	for i := 0; i < len(blocks); i++ {
		for j := 0; j < len(blocks[i]); j++ {
			if len(tblocks[j]) == 0 {
				tblocks[j] = make([]byte, len(blocks))
			}
			tblocks[j][i] = blocks[i][j]
		}
	}
	return tblocks
}

func BlocksEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Performs PKCS#7 Padding on the input `in` and block size `k`.
// Assumes 0 > `k` < 256
// Reference: https://tools.ietf.org/html/rfc5652#section-6.3
func Pkcs7Padding(in []byte, k int) []byte {
	lth := len(in)
	pd := k - (lth % k) // padding character and padding length

	for i := 0; i < pd; i++ {
		in = append(in, byte(pd))
	}
	return in
}
