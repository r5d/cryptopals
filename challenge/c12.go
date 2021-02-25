// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C12() {
	sheep := byte(65)
	unknown := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`
	key, err := lib.RandomBytes(16)
	if err != nil {
		fmt.Printf("key generatation error: %v", err)
	}
	encrypt := func(in []byte) []byte {
		return lib.AESEncryptECB(append(in, lib.Base64ToBytes(unknown)...), key)
	}

	freshSheepBytes := func(n int) []byte {
		in := make([]byte, n)
		for i := 0; i < n; i++ {
			in[i] = sheep
		}
		return in
	}
	findBlockSize := func() int {
		in := make([]byte, 0)

		in = append(in, sheep)
		is := len(encrypt(in)) // initial size
		bs := 0                // block size
		for {
			in = append(in, sheep)
			bs = len(encrypt(in))
			if bs != is {
				return (bs - is)
			}
		}
	}
	findUnknownStringCharacteristics := func(blocksize int) (int, int) {
		in := make([]byte, 0)
		c_sz := len(encrypt(in))    // Cipher size
		nblocks := c_sz / blocksize // number of blocks

		// Figure out ize of unknown string.
		for {
			in = append(in, sheep)
			bs := len(encrypt(in))
			if bs != c_sz {
				return nblocks, (c_sz - len(in))
			}
		}

	}
	isOracleUsingECB := func() bool {
		in := lib.StrToBytes("OliverMkTukudzi OliverMkTukudzi OliverMkTukudzi")
		oo := encrypt(in)
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
	decipherUnknownStringIter := func(blocksize, block, n int, in, ds []byte) ([]byte, []byte) {
		oo := encrypt(in[0:(blocksize - n)])

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
			oo = encrypt(in)

			if lib.BlocksEqual(nbl, oo[0:16]) {
				ds = append(ds, in[15])
				return in, ds
			}
		}
		panic("not found!")
	}

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

// Output:
// Unknown String:
// Rollin' in my 5.0
// With my rag-top down so my hair can blow
// The girlies on standby waving just to say hi
// Did you stop? No, I just drove by
