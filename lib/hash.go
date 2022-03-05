// Copyright © 2021 siddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// (a + b + ...) mod 2^32
func shaAdd(n ...uint32) uint32 {
	sum := uint64(0)
	for _, v := range n {
		sum += uint64(v)
	}
	return uint32(sum & 0xFFFFFFFF)
}

// Circular Right Shift
func shaRotr(x uint32, n uint) uint32 {
	return (x >> n) | (x << (32 - n))
}

// Circular Left Shift
func shaRotl(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}

// Right Shift
func shaShr(x uint32, n uint) uint32 {
	return x >> n
}
