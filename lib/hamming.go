// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

func HammingDistance(a, b string) int {
	if len(a) != len(b) {
		return -1 // Fail.
	}

	d := 0
	for i := 0; i < len(a); i++ {
		c := a[i] ^ b[i]
		d += setBits(c)
	}
	return d
}

// Returns number of set bits.
func setBits(b byte) int {
	var c byte = 0
	for i := 0; i < 8; i++ {
		c += b & 0x1
		b = b >> 1
	}
	return int(c)
}
