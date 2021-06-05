// Copyright © 2020 rsiddharth <s@ricketyspace.net>
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
	common := make([]byte, 0)
	switch l := len(bbytes); {
	case l == 1:
		common = bbytes[0]
	case l > 1:
		commonRest := BytesInCommon(bbytes[1:])
		for _, b := range bbytes[0] {
			if ByteInBytes(b, commonRest) {
				common = append(common, b)
			}
		}
	}
	return common
}
