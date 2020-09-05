// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import "math/rand"

func init() {
	rand.Seed(42)
}

func HammingDistance(a, b []byte) int {
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

// Returns average key size with minimum normalized hamming distance.
// 'keyMin' is the minimum key size
// 'keyMax' is the maximum key size
// 'iterate' is the number of times to iterate.
func KeySizeWithMinDistanceIter(keyMin, keyMax, iterate int) int {
	sum := 0
	avg := 0.0
	for i := 0; i < iterate; i++ {
		sum += KeySizeWithMinDistance(keyMin, keyMax)
	}
	avg = float64(sum) / float64(iterate)

	return int(avg)
}

// Returns key size with minimum normalized hamming distance
// 'keyMin' is the minimum key size
// 'keyMax' is the maximum key size
func KeySizeWithMinDistance(keyMin, keyMax int) int {
	var mk int = 0         // Key size with min distance.
	var md float64 = 100.0 // Distance for key size 'mk'.
	for k := keyMin; k <= keyMax; k++ {
		p := genKey(k)
		q := genKey(k)

		// Compute distance.
		d := HammingDistance(p, q)

		nd := float64(d) / float64(k)
		if nd < md {
			mk = k
			md = nd
		}
	}
	return mk
}

// Generates a key of size 'size' bytes.
func genKey(size int) []byte {
	bs := make([]byte, size, size)
	rand.Read(bs)

	return bs
}
