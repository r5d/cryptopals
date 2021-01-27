// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"
	"ricketyspace.net/cryptopals/lib"
)

func C15() {
	ice := lib.StrToBytes("ICE ICE BABY")
	fmt.Printf("ice: %v\n", ice)

	padded_ice := lib.Pkcs7Padding(ice, 16)
	fmt.Printf("ice padded: %v\n", padded_ice)

	unpadded_ice := lib.Pkcs7PaddingUndo(padded_ice)
	for i := 0; i < len(ice); i++ {
		if ice[i] != unpadded_ice[i] {
			panic("padding undo failed!")
		}
	}
	fmt.Printf("unpadded ice: %v\n", unpadded_ice)

	// Will fail; commented out.
	// bad_ice := append(ice, []byte{5, 5, 5, 5}...)
	// fmt.Printf("bad ice: %v\n", bad_ice)
	// lib.Pkcs7PaddingUndo(bad_ice)

	// Will fail; commented out.
	// evil_ice := append(ice, []byte{1, 2, 3, 4}...)
	// fmt.Printf("evil ice: %v\n", evil_ice)
	// lib.Pkcs7PaddingUndo(evil_ice)
}

// Output:
// ice: [73 67 69 32 73 67 69 32 66 65 66 89]
// ice padded: [73 67 69 32 73 67 69 32 66 65 66 89 4 4 4 4]
// unpadded ice: [73 67 69 32 73 67 69 32 66 65 66 89]
