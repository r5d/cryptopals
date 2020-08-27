// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package main

import (
	"fmt"
	"ricketyspace.net/cryptopals/enc"
)

func main() {
	hex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	b64 := enc.HexToBase64(hex)

	fmt.Printf("b64(0x%v) = %v\n", hex, b64)
}
