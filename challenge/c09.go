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
