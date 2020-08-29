// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"
	"ricketyspace.net/cryptopals/enc"
)

func C2() {
	a := "1c0111001f010100061a024b53535009181c"
	b := "686974207468652062756c6c277320657965"
	c := enc.FixedXOR(a, b)

	fmt.Printf("XOR(%v ^ %v) = %v\n", a, b, c)
}
