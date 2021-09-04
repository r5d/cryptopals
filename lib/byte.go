// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// Returns true if byte `b` is in `bs`
func ByteInBytes(b byte, bs []byte) bool {
	for _, bi := range bs {
		if b == bi {
			return true
		}
	}
	return false
}

// Returns bytes that are common in the given array of array of bytes
// `bbytes`.
func BytesInCommon(bbytes [][]byte) []byte {
	var common []byte
	switch l := len(bbytes); {
	case l == 1:
		common = make([]byte, len(bbytes[0]))
		copy(common, bbytes[0])
	case l > 1:
		common = make([]byte, 0)
		commonRest := BytesInCommon(bbytes[1:])
		for _, b := range bbytes[0] {
			if ByteInBytes(b, commonRest) {
				common = append(common, b)
			}
		}
	}
	return common
}

func ByteIsUpper(b byte) bool {
	if 'A' <= b && b <= 'Z' {
		return true
	}
	return false
}

func BytesEqual(a, b []byte) bool {
	return BlocksEqual(a, b)
}
