// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// Both 'a' and 'b' must be hex encoded string.
func FixedXOR(a, b string) string {
	cs := ""
	if len(a) != len(b) {
		return cs
	}

	ab := []byte(a)
	bb := []byte(b)
	for i := 0; i < len(ab); i++ {
		p := HexCharToDec(ab[i])
		q := HexCharToDec(bb[i])
		r := DecToHexChar(p ^ q)

		cs += string(r)
	}
	return cs
}

func FixedXORBytes(as, bs []byte) []byte {
	if len(as) != len(bs) {
		return make([]byte, 0)
	}

	cs := make([]byte, len(as))
	for i := 0; i < len(as); i++ {
		cs[i] = as[i] ^ bs[i]
	}
	return cs
}

// Both 'data' and 'key' need to be plain ascii string.
func RepeatingXOR(data, key []byte) []byte {
	xs := make([]byte, 0)
	if len(data) < 1 || len(key) < 1 {
		return xs
	}

	lk := len(key)
	for i, ki := 0, 0; i < len(data); i++ {
		if ki == lk {
			ki = 0
		}

		// xor a byte
		eb := data[i] ^ key[ki]

		// append to result
		xs = append(xs, eb)

		ki += 1
	}
	return xs
}
