// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C14() {
	sheep := byte(65)
	unknown := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`
	key, err := lib.RandomBytes(16)
	if err != nil {
		fmt.Printf("key generatation error: %v", err)
	}
	oracleRandom, err := lib.RandomBytes(int(lib.RandomInt(1, 4096)))
	if err != nil {
		fmt.Printf("oracle random generation error: %v", err)
	}
	encrypt := func(in []byte) []byte {
		in = append(oracleRandom, in...)
		in = append(in, lib.Base64ToBytes(unknown)...)
		return lib.AESEncryptECB(in, key)
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
		bs := 0
		for {
			in = append(in, sheep)
			bs = len(encrypt(in))
			if bs != is {
				return (bs - is)
			}
		}
	}
	findPrefixLen := func(blocksize int) (int, int, int) {
		// Make two sheep blocks.
		tsb := append(freshSheepBytes(blocksize), freshSheepBytes(blocksize)...)

		v := []byte{}
		index := 0
		found := false
		for {
			in := append(v, tsb...)
			c := encrypt(in)
			index, found = lib.HasConsecutiveMatchingBlocks(c, blocksize)
			if found {
				break
			}
			// Add another sheep
			v = append(v, sheep)
		}
		l := index - len(v)
		nrpb := l / blocksize // number of randbox prefix blocks
		rpo := 0              // random prefix offset
		if l%blocksize != 0 {
			nrpb += 1
			rpo = blocksize - (l % blocksize)
		}
		return l, nrpb, rpo
	}
	// Finds the cipher block size and the length of the unknown string
	// (target-bytes).
	findUnknownStringNumBlocksLength := func(rpl, blocksize int) (int, int) {
		padding := blocksize - (rpl % blocksize)
		in := make([]byte, padding)
		c_sz := len(encrypt(in)) // Cipher size

		nblocks := c_sz / blocksize            // total number of blocks
		rblocks := (rpl + padding) / blocksize // number of blocks of random prefix
		ublocks := nblocks - rblocks           // number of blocks of unknown string
		// Figure out size of unknown string.
		for {
			in = append(in, sheep)
			bs := len(encrypt(in))
			if bs != c_sz {
				return ublocks, (c_sz - len(in) - rpl)
			}
		}
	}
	// `nrpb` number of random prefix blocks
	// `rpo` random prefix offset
	// `blocksize` is the size of a block
	// `block` is the nth block that is being deciphered
	// `n` is the nth byte of the block `block` that is going to be deciphered.
	// `in` (n-1)th block that is known
	// `ds` deciphered unknown string
	decipherOneByte := func(nrpb, rpo, blocksize, block, n int, in, ds []byte) ([]byte, []byte) {
		oo := encrypt(in[0:(len(in) - n)])

		s := (nrpb * blocksize) + 16*(block-1)
		e := s + 16
		nbl := oo[s:e] // nth block of the cipher

		// Shift `in` to the left by one place.
		for i := rpo; i < len(in)-1; i++ {
			in[i] = in[i+1]
		}

		// Try all combinations.
		for i := 0; i < 256; i++ {
			in[len(in)-1] = byte(i)
			oo = encrypt(in)

			if lib.BlocksEqual(nbl,
				oo[(nrpb*blocksize):(nrpb*blocksize)+16]) {
				ds = append(ds, in[len(in)-1])
				return in, ds
			}
		}
		panic("not found!")
	}
	blocksize := findBlockSize()
	rpl, nrpb, rpo := findPrefixLen(blocksize)
	nbl, us_sz := findUnknownStringNumBlocksLength(
		rpl, blocksize)
	in := append(freshSheepBytes(rpo), // random prefix offset
		freshSheepBytes(blocksize)...)
	ds := make([]byte, 0) // deciphered unknown string in bytes
	for i := 0; i < nbl; i++ {
		nby := blocksize
		if i == nbl-1 {
			nby = us_sz % blocksize
		}
		for j := 0; j < nby; j++ {
			in, ds = decipherOneByte(nrpb, rpo, blocksize,
				i+1, j+1, in, ds)
		}
		s := 16 * i
		e := s + 16
		in = append(freshSheepBytes(rpo), ds[s:e]...)
	}
	fmt.Printf("Unknown String:\n%v", lib.BytesToStr(ds))
}

// Output:
// Unknown String:
// Rollin' in my 5.0
// With my rag-top down so my hair can blow
// The girlies on standby waving just to say hi
// Did you stop? No, I just drove by
