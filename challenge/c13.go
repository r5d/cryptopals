// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"
	"ricketyspace.net/cryptopals/lib"
)

func C13() {
	adminBlock := lib.BytesToStr(lib.Pkcs7Padding(lib.StrToBytes("admin"), 16))
	ep := lib.WebProfileFor("foo@abacus" + adminBlock)
	encryptedEP := lib.WebEncryptProfile(ep)
	adminBlockCipher := encryptedEP[16:32] // Second block in the cipher

	ep = lib.WebProfileFor("foo@abacus")
	encryptedEP = lib.WebEncryptProfile(ep)
	for i := 0; i < 16; i++ { // Replace last block with the admin cipher block.
		encryptedEP[32+i] = adminBlockCipher[i]
	}
	adminEP := lib.WebDecryptProfile(encryptedEP)
	adminProfile := lib.WebDecodeProfile(adminEP)
	fmt.Printf("Admin Encoded Profile: %v\n", adminEP)
	fmt.Printf("Admin Profile: %v\n", adminProfile)
}

// Output:
// Admin Encoded Profile: email=foo@abacus&uid=10001&role=admin
// Admin Profile: map[email:foo@abacus role:admin uid:10001]
