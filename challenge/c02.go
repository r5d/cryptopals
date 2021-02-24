// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C2() {
	a := "1c0111001f010100061a024b53535009181c"
	b := "686974207468652062756c6c277320657965"
	c := lib.FixedXOR(a, b)

	fmt.Printf("XOR(%v ^ %v) = %v\n", a, b, c)
}

// Output:
//
// XOR(1c0111001f010100061a024b53535009181c ^ 686974207468652062756c6c277320657965) = 746865206b696420646f6e277420706c6179
