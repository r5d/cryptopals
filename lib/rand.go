// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import (
	"crypto/rand"
	"math/big"
)

// Return a random number from range [min, max]
func RandomInt(min, max int64) int64 {
	if min >= max {
		panic("RandomInt: min cannot be >= max!")
	}

	var rn *big.Int
	var err error
	for {
		rn, err = rand.Int(rand.Reader, big.NewInt(max+1))
		if err != nil {
			panic(err)
		}
		if rn.Int64() >= min {
			return rn.Int64()
		}
	}
}

func RandomKey(size int) ([]byte, error) {
	k := make([]byte, size)
	_, err := rand.Read(k)
	if err != nil {
		return []byte{}, err
	}
	return k, nil
}

// Randomly generates `min` to `max` bytes.
func randomBytes(min, max int64) []byte {
	bs := make([]byte, RandomInt(min, max))
	_, err := rand.Read(bs)
	if err != nil {
		panic(err)
	}
	return bs
}
