// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"
	"ricketyspace.net/cryptopals/lib"
)

var sheep byte = 65

func C12() {
	if !isOracleUsingECB() {
		panic("oracle not using ecb mode")
	}

	blocksize := findBlockSize()
	nbl, us_sz := findUnknownStringCharacteristics(blocksize)
	in := freshSheepBytes(blocksize)
	ds := make([]byte, 0) // deciphered unknown string in bytes
	for i := 0; i < nbl; i++ {
		nby := blocksize
		if i == nbl-1 {
			nby = us_sz % blocksize
		}
		for j := 0; j < nby; j++ {
			in, ds = decipherUnknownStringIter(blocksize, i+1, j+1,
				in, ds)
		}
		s := 16 * i
		e := s + 16
		copy(in, ds[s:e])
	}
	fmt.Printf("Unknown String:\n%v", lib.BytesToStr(ds))
}

func freshSheepBytes(n int) []byte {
	in := make([]byte, n)
	for i := 0; i < n; i++ {
		in[i] = sheep
	}
	return in
}

func findBlockSize() int {
	in := make([]byte, 0)

	in = append(in, sheep)
	is := len(lib.OracleAESEncryptECB(in)) // initial size
	bs := 0                                // block size
	for {
		in = append(in, sheep)
		bs = len(lib.OracleAESEncryptECB(in))
		if bs != is {
			return (bs - is)
		}
	}
}

func findUnknownStringCharacteristics(blocksize int) (int, int) {
	in := make([]byte, 0)
	c_sz := len(lib.OracleAESEncryptECB(in)) // Cipher size
	nblocks := c_sz / blocksize              // number of blocks

	// Figure out ize of unknown string.
	for {
		in = append(in, sheep)
		bs := len(lib.OracleAESEncryptECB(in))
		if bs != c_sz {
			return nblocks, (c_sz - len(in))
		}
	}

}

func isOracleUsingECB() bool {
	in := lib.StrToBytes("OliverMkTukudzi OliverMkTukudzi OliverMkTukudzi")
	oo := lib.OracleAESEncryptECB(in)
	if lib.CipherUsesECB(oo) != nil {
		return true
	}
	return false
}

// `blocksize` is the size of a block
// `block` is the nth block that is being deciphered
// `n` is the nth byte of the block `block` that is going to be deciphered.
// `in` (n-1)th block that is known
// `ds` deciphered unknown string
func decipherUnknownStringIter(blocksize, block, n int, in, ds []byte) ([]byte, []byte) {
	oo := lib.OracleAESEncryptECB(in[0:(blocksize - n)])

	s := 16 * (block - 1)
	e := s + 16
	nbl := oo[s:e] // nth block of the cipher

	// Shift `in` to the left by one place.
	for i := 0; i < blocksize-1; i++ {
		in[i] = in[i+1]
	}

	// Try all combinations.
	for i := 0; i < 256; i++ {
		in[15] = byte(i)
		oo = lib.OracleAESEncryptECB(in)

		if lib.BlocksEqual(nbl, oo[0:16]) {
			ds = append(ds, in[15])
			return in, ds
		}
	}
	panic("not found!")
}

// Output:
// Unknown String:
// Rollin' in my 5.0
// With my rag-top down so my hair can blow
// The girlies on standby waving just to say hi
// Did you stop? No, I just drove by
