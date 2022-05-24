// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C29() {
	// Original message.
	msg := lib.StrToBytes("comment1=cooking%20MCs;userdata=foo;" +
		"comment2=%20like%20a%20pound%20of%20bacon")

	// Random secret (unknown to attacker)
	sec, err := lib.RandomBytes(int(lib.RandomInt(8, 100)))
	if err != nil {
		fmt.Printf("Error: unable generate secret\n")
	}

	// `m` is the original message.
	// `hvs` is the hash values.
	// `sl` is the secret key length (guess).
	genForgedMsgMac := func(m []byte, hvs []uint32, sl int) ([]byte, []byte) {
		mf := make([]byte, len(m))
		copy(mf, m)
		mf = append(mf, lib.MDPadding(sl+len(m))...)
		mf = append(mf, lib.StrToBytes(";admin=true")...)

		// Generate SHA1 MAC for forged message.
		sha1 := lib.Sha1{}
		sha1.Init(hvs)
		sha1.Message(lib.StrToBytes(";admin=true"))
		// Fudge message length to forged message length.
		sha1.MsgLen = sl + len(mf)

		return mf, sha1.Hash()
	}

	// Returns true if the message is forged.
	isForged := func(msg, mac []byte) bool {
		sha1 := lib.Sha1{}
		sha1.Init([]uint32{})
		if sha1.MacVerify(sec, msg, mac) {
			return true
		}
		return false
	}

	// Generate SHA1 MAC of original message and get the hash
	// values.
	sha1 := lib.Sha1{}
	sha1.Init([]uint32{})
	msgHVs := lib.BytesToUint32s(sha1.Mac(sec, msg)) // Hash values.

	// Try to forge message with different secret prefix lengths.
	sl := 1
	for {
		mf, mac := genForgedMsgMac(msg, msgHVs, sl)
		if isForged(mf, mac) {
			fmt.Printf("SHA1-MAC successfully forged: %x\n", mac)
			fmt.Printf("Forged Message: %s\n", mf)
			fmt.Printf("Secret prefix length: %v\n", sl)
			break
		}
		sl += 1
	}

}

// Output:
// SHA1-MAC successfully forged: 0cb8bbbaa6090c86a8b7110788d6241b20df7c99
// Forged Message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20baconh;admin=true
// Secret prefix length: 96
