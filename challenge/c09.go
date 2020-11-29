// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"
	"ricketyspace.net/cryptopals/lib"
)

func C9() {
	in := lib.StrToBytes("YELLOW SUBMARINE")
	in_padded := lib.Pkcs7Padding(in, 24)
	fmt.Printf("IN:  %v\nOUT: %v\n", in, in_padded)
}

// Output:
//
// IN:  [89 69 76 76 79 87 32 83 85 66 77 65 82 73 78 69]
// OUT: [89 69 76 76 79 87 32 83 85 66 77 65 82 73 78 69 8 8 8 8 8 8 8 8]

