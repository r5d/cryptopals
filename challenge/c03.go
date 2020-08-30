// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"
	"ricketyspace.net/cryptopals/lib"
)

func C3() {
	hs := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	k, ds, scr := lib.XORCrackSingleKey(hs)

	fmt.Printf("Key is '%c' (Score: %v)\n", k, scr)
	fmt.Printf("Decrypted string: %v\n", ds)
}
