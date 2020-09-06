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
		if j == 8 {
			j = 0
			k += 1
		}
	}
	return blocks
}
