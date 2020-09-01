// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"
	"ricketyspace.net/cryptopals/lib"
)

var icebaby string = `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

var key string = "ICE"

func C5() {
	es := lib.RepeatingXOR(icebaby, key)
	hs := lib.AsciiStrToHexStr(es)

	fmt.Printf("RepeatingXOR('%v', '%v') = %v\n", icebaby, key, hs)
}
