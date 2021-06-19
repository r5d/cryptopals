// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C5() {
	icebaby := lib.StrToBytes(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)
	key := lib.StrToBytes("ICE")
	eb := lib.RepeatingXOR(icebaby, key)
	hs := lib.AsciiStrToHexStr(lib.BytesToStr(eb))
	fmt.Printf("RepeatingXOR('%s', '%s') = %v\n", icebaby, key, hs)
}

// Output:
//
// RepeatingXOR('Burning 'em, if you ain't quick and nimble
// I go crazy when I hear a cymbal', 'ICE') = 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
