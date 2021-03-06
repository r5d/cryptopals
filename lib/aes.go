// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// Generates counter function for AES CTR mode.
func AESGenCTRFunc(nonce uint64) func() []byte {
	ctr := uint64(0) // Counter
	ff := uint64(0xFF)
	cf := func() []byte {
		cb := make([]byte, 16) // counter block
		var i, j uint
		// Put nonce in the first 8 bytes in cb in little endian format
		for i = 0; i < 8; i++ {
			n := nonce & (ff << (i * 8)) // Reset all except the i^th byte of the nonce
			cb[i] = byte(n >> (i * 8))   // Retrieve i^th byte of the nonce
		}
		// Put counter in the next 8 bytes in cb in little endian format
		for i, j = 8, 0; i < 16; i, j = i+1, j+1 {
			n := ctr & (ff << (j * 8)) // Reset all except the j^th byte of the counter
			cb[i] = byte(n >> (j * 8)) // Retrieve j^th byte of the counter
		}
		ctr += 1 // Increment counter by 1
		return cb
	}
	return cf
}

func AESEncryptCTR(plain, key []byte, ctrFunc func() []byte) ([]byte, error) {
	if len(key) != 16 {
		return []byte{}, CPError{"key length != 16"}
	}
	return aesCipherCTR(plain, key, ctrFunc)
}

func AESDecryptCTR(cipher, key []byte, ctrFunc func() []byte) ([]byte, error) {
	if len(key) != 16 {
		return []byte{}, CPError{"key length != 16"}
	}
	return aesCipherCTR(cipher, key, ctrFunc)
}

func aesCipherCTR(in, key []byte, ctrFunc func() []byte) ([]byte, error) {
	iter := len(in) / 16
	if len(in)%16 != 0 {
		iter += 1
	}
	output := make([]byte, 0)
	for i := 0; i < iter; i++ {
		ib := ctrFunc()
		if len(ib) != 16 {
			return []byte{}, CPError{"ctr length != 16"}
		}
		s := (i * 16)
		e := (i * 16) + 16
		if e > len(in) {
			e = len(in)
		}
		c := in[s:e]
		output = append(output, FixedXORBytes(AESCipher(ib, key)[0:len(c)], c)...)
	}
	return output, nil
}

func AESEncryptCBC(plain, key, iv []byte) []byte {
	// Pad input
	plain = Pkcs7Padding(plain, 16)

	iter := len(plain) / 16

	lc := iv
	output := make([]byte, 0)
	for i := 0; i < iter; i++ {
		s := (i * 16)
		e := (i * 16) + 16
		p := plain[s:e]
		c := AESCipher(FixedXORBytes(p, lc), key)
		output = append(output, c...)

		lc = c
	}
	return output
}

func AESDecryptCBC(cipher, key, iv []byte) ([]byte, error) {
	iter := len(cipher) / 16

	lc := iv
	output := make([]byte, 0)
	for i := 0; i < iter; i++ {
		s := (i * 16)
		e := (i * 16) + 16
		c := cipher[s:e]
		output = append(output, FixedXORBytes(AESInvCipher(c, key), lc)...)

		lc = c
	}

	// Undo padding
	output, err := Pkcs7PaddingUndo(output)

	return output, err
}

func AESEncryptECB(plain, key []byte) []byte {
	// Pad input
	plain = Pkcs7Padding(plain, 16)

	iter := len(plain) / 16

	// Encrypt 16 bytes at a time.
	output := make([]byte, 0)
	for i := 0; i < iter; i++ {
		s := (i * 16)
		e := (i * 16) + 16
		output = append(output, AESCipher(plain[s:e], key)...)
	}

	return output
}

func AESDecryptECB(cipher, key []byte) []byte {
	iter := len(cipher) / 16

	// Decrypt 16 bytes at a time.
	output := make([]byte, 0)
	for i := 0; i < iter; i++ {
		s := (i * 16)
		e := (i * 16) + 16
		output = append(output, AESInvCipher(cipher[s:e], key)...)
	}

	// Undo padding
	output, _ = Pkcs7PaddingUndo(output)

	return output
}

func AESCipher(in, ky []byte) []byte {
	nb := 4
	nr := 10

	// Generate key schedule from key.
	ks := aesKeyExpansion(ky)

	// Make state from input and do first round key
	// transformation.
	state := aesMkState(in)
	state = aesAddRoundKey(state, ks[0:4])

	for round := 1; round <= nr-1; round++ {
		state = aesSubBytes(state)
		state = aesShiftRows(state)
		state = aesMixColumns(state)
		state = aesAddRoundKey(state, ks[(round*nb):((round+1)*nb)])
	}
	state = aesSubBytes(state)
	state = aesShiftRows(state)
	state = aesAddRoundKey(state, ks[(nr*nb):((nr+1)*nb)])

	// Make output.
	output := make([]byte, 4*nb)
	i := 0
	for c := 0; c < nb; c++ {
		for r := 0; r < 4; r++ {
			output[i] = state[r][c]
			i++
		}
	}

	return output
}

func AESInvCipher(in, ky []byte) []byte {
	nb := 4
	nr := 10

	// Generate key schedule from key.
	ks := aesKeyExpansion(ky)

	// Make state from input and do first round key
	// transformation.
	state := aesMkState(in)
	state = aesAddRoundKey(state, ks[(nr*nb):((nr+1)*nb)])

	for round := nr - 1; round >= 1; round-- {
		state = aesInvShiftRows(state)
		state = aesInvSubBytes(state)
		state = aesAddRoundKey(state, ks[(round*nb):((round+1)*nb)])
		state = aesInvMixColumns(state)
	}
	state = aesInvShiftRows(state)
	state = aesInvSubBytes(state)
	state = aesAddRoundKey(state, ks[0:nb])

	// Make output.
	output := make([]byte, 4*nb)
	i := 0
	for c := 0; c < nb; c++ {
		for r := 0; r < 4; r++ {
			output[i] = state[r][c]
			i++
		}
	}
	return output
}

func aesMixColumns(state [][]byte) [][]byte {

	// Initialize new state.
	n_state := make([][]byte, 4)
	nb := 4
	for r := 0; r < 4; r++ {
		n_state[r] = make([]byte, nb)
	}

	// Mix columns transformation.
	for c := 0; c < nb; c++ {
		n_state[0][c] = GFMultiply(0x02, state[0][c]) ^ GFMultiply(0x03, state[1][c]) ^ state[2][c] ^ state[3][c]
		n_state[1][c] = state[0][c] ^ GFMultiply(0x02, state[1][c]) ^ GFMultiply(0x03, state[2][c]) ^ state[3][c]
		n_state[2][c] = state[0][c] ^ state[1][c] ^ GFMultiply(0x02, state[2][c]) ^ GFMultiply(0x03, state[3][c])
		n_state[3][c] = GFMultiply(0x03, state[0][c]) ^ state[1][c] ^ state[2][c] ^ GFMultiply(0x02, state[3][c])
	}
	return n_state
}

func aesInvMixColumns(state [][]byte) [][]byte {

	// Initialize new state.
	n_state := make([][]byte, 4)
	nb := 4
	for r := 0; r < 4; r++ {
		n_state[r] = make([]byte, nb)
	}

	// Inverse mix columns transformation.
	for c := 0; c < nb; c++ {
		n_state[0][c] = GFMultiply(0x0e, state[0][c]) ^ GFMultiply(0x0b, state[1][c]) ^ GFMultiply(0x0d, state[2][c]) ^ GFMultiply(0x09, state[3][c])
		n_state[1][c] = GFMultiply(0x09, state[0][c]) ^ GFMultiply(0x0e, state[1][c]) ^ GFMultiply(0x0b, state[2][c]) ^ GFMultiply(0x0d, state[3][c])
		n_state[2][c] = GFMultiply(0x0d, state[0][c]) ^ GFMultiply(0x09, state[1][c]) ^ GFMultiply(0x0e, state[2][c]) ^ GFMultiply(0x0b, state[3][c])
		n_state[3][c] = GFMultiply(0x0b, state[0][c]) ^ GFMultiply(0x0d, state[1][c]) ^ GFMultiply(0x09, state[2][c]) ^ GFMultiply(0x0e, state[3][c])
	}
	return n_state
}

func aesSubBytes(state [][]byte) [][]byte {
	nb := 4
	for r := 0; r < 4; r++ {
		for c := 0; c < nb; c++ {
			x := state[r][c] >> 4
			y := state[r][c] & 0x0f

			state[r][c] = sbox[x][y]
		}
	}
	return state
}

func aesInvSubBytes(state [][]byte) [][]byte {
	nb := 4
	for r := 0; r < 4; r++ {
		for c := 0; c < nb; c++ {
			x := state[r][c] >> 4
			y := state[r][c] & 0x0f

			state[r][c] = isbox[x][y]
		}
	}
	return state
}

func aesShiftRows(state [][]byte) [][]byte {
	n_state := make([][]byte, 4) // New state.

	nb := 4
	for r := 0; r < 4; r++ {
		n_state[r] = make([]byte, nb)
		for c := 0; c < nb; c++ {
			n_state[r][c] = state[r][(c+r)%nb]

		}
	}
	return n_state
}

func aesInvShiftRows(state [][]byte) [][]byte {
	n_state := make([][]byte, 4) // New state.

	nb := 4
	for r := 0; r < 4; r++ {
		n_state[r] = make([]byte, nb)
		for c := 0; c < nb; c++ {
			n_state[r][(c+r)%nb] = state[r][c]
		}
	}
	return n_state
}

func aesAddRoundKey(state, ks [][]byte) [][]byte {
	if len(ks) != 4 {
		return state
	}
	nb := 4

	// Get tranpose of ks.
	ks_t := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		ks_t[i] = make([]byte, 4)
		for j := 0; j < 4; j++ {
			ks_t[i][j] = ks[j][i]
		}
	}

	// Round key transformation.
	for c := 0; c < nb; c++ {
		for r := 0; r < 4; r++ {
			state[r][c] = state[r][c] ^ ks_t[r][c]
		}
	}
	return state
}

// Makes and returns initial the state array from 16-byte input 'in'.
func aesMkState(in []byte) [][]byte {
	if len(in) != 16 {
		return [][]byte{}
	}
	nb := 4
	state := make([][]byte, 4)

	for r := 0; r < 4; r++ {
		state[r] = make([]byte, nb)
		for c := 0; c < nb; c++ {
			state[r][c] = in[r+(4*c)]
		}
	}
	return state
}

// Returns a key schedule (176 bytes, 44 4-byte words) given a key 'k'
// (16 bytes, 4 4-byte words).
func aesKeyExpansion(k []byte) [][]byte {
	ks := make([][]byte, 44) // key schedule
	nk := 4
	nb := 4
	nr := 10

	// Generate first 4 (Nk) words of the key schedule from the
	// key 'k'
	for i := 0; i < nk; i++ {
		ks[i] = make([]byte, 4)

		ks[i][0] = k[(4*i)+0]
		ks[i][1] = k[(4*i)+1]
		ks[i][2] = k[(4*i)+2]
		ks[i][3] = k[(4*i)+3]
	}

	// Generate the rest of the key schedule.
	for i := 4; i < (nb * (nr + 1)); i++ {
		tmp := make([]byte, 4)
		copy(tmp, ks[i-1])

		if i%nk == 0 {
			tmp = FixedXORBytes(aesSubWord(aesRotWord(tmp)), rcon[i/nk])
		}
		ks[i] = make([]byte, 4)
		ks[i] = FixedXORBytes(ks[i-nk], tmp)
	}

	return ks
}

// Performs a cyclic permutation to the left on the 4-byte word.
func aesRotWord(w []byte) []byte {
	for i := 1; i < 4; i++ {
		t := w[i-1]
		w[i-1] = w[i]
		w[i] = t
	}
	return w
}

// Performs S-Box transformation on the 4-byte word.
func aesSubWord(w []byte) []byte {
	sw := make([]byte, 4)

	for i := 0; i < 4; i++ {
		r := w[i] >> 4
		c := w[i] & 0x0f

		sw[i] = sbox[r][c]
	}
	return sw
}

// Generated using https://github.com/mvaneerde/blog/blob/061f/rijndael/s-box.pl
var sbox [16][16]byte = [16][16]byte{
	{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
	{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
	{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
	{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
	{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
	{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
	{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
	{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
	{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
	{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
	{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
	{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
	{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
	{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
	{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
	{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16},
}

// Generated using https://github.com/mvaneerde/blog/blob/061f/rijndael/s-box.pl
var isbox [16][16]byte = [16][16]byte{
	{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
	{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
	{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
	{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
	{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
	{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
	{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
	{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
	{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
	{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
	{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
	{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
	{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
	{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
	{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
	{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d},
}

// Round constants for 1 <= i <= 10
// From https://en.wikipedia.org/wiki/AES_key_schedule#Rcon
var rcon [11][]byte = [11][]byte{
	{0x00, 0x00, 0x00, 0x00}, // i = 0; dummy
	{0x01, 0x00, 0x00, 0x00},
	{0x02, 0x00, 0x00, 0x00},
	{0x04, 0x00, 0x00, 0x00},
	{0x08, 0x00, 0x00, 0x00},
	{0x10, 0x00, 0x00, 0x00},
	{0x20, 0x00, 0x00, 0x00},
	{0x40, 0x00, 0x00, 0x00},
	{0x80, 0x00, 0x00, 0x00},
	{0x1b, 0x00, 0x00, 0x00},
	{0x36, 0x00, 0x00, 0x00},
}
