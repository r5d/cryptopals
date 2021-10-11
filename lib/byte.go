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

func BytesToUint32s(bs []byte) []uint32 {
	u32s := make([]uint32, 0)

	ui := uint32(0) // 32-bit word.
	ab := uint(32)  // Available bits in ui.
	for _, b := range bs {
		if ab == 0 {
			// ui full; add to u32s and reset ui.
			u32s = append(u32s, ui)
			ui = uint32(0)
			ab = 32
		}
		// Stuff byte into ui.
		ui = ui | uint32(b)<<(ab-8)
		ab = ab - 8
	}
	if ui > 0 {
		u32s = append(u32s, ui)
	}
	return u32s
}

func BytesToUint32sLittleEndian(bs []byte) []uint32 {
	u32s := make([]uint32, 0)

	ui := uint32(0) // 32-bit word.
	ab := uint(0)   // Occupied bits in ui
	for _, b := range bs {
		if ab == 32 {
			// ui full; add to u32s and reset ui.
			u32s = append(u32s, ui)
			ui = uint32(0)
			ab = 0
		}
		// Stuff byte into ui.
		ui = ui | uint32(b)<<ab
		ab = ab + 8
	}
	if ui > 0 {
		u32s = append(u32s, ui)
	}
	return u32s
}
