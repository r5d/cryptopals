// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

// Cryptopals #18 - Implement CTR, the stream cipher mode
func C18() {
	cipher := lib.Base64ToBytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	key := lib.StrToBytes("YELLOW SUBMARINE")
	ctrFunc := lib.AESGenCTRFunc(0)
	plain, err := lib.AESDecryptCTR(cipher, key, ctrFunc)
	if err != nil {
		fmt.Printf("decryption failed: %v", err)
	}
	fmt.Printf("%v\n", lib.BytesToStr(plain))
}

// Output:
// Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby
