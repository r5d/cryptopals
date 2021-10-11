// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C30() {
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
		mf = append(mf, lib.Md4Padding(sl+len(m))...)
		mf = append(mf, lib.StrToBytes(";admin=true")...)

		// Generate MD4 MAC for forged message.
		md4 := lib.Md4{}
		md4.Init(hvs)
		md4.Message(lib.StrToBytes(";admin=true"))
		// Fudge message length to forged message length.
		md4.MsgLen = sl + len(mf)

		return mf, md4.Hash()
	}

	// Returns true if the message is forged.
	isForged := func(msg, mac []byte) bool {
		md4 := lib.Md4{}
		md4.Init([]uint32{})
		if md4.MacVerify(sec, msg, mac) {
			return true
		}
		return false
	}

	// Generate MD4 MAC of original message and get the hash
	// values.
	md4 := lib.Md4{}
	md4.Init([]uint32{})
	msgHVs := lib.BytesToUint32sLittleEndian(md4.Mac(sec, msg)) // Hash values.

	// Try to forge message with different secret prefix lengths.
	sl := 1
	for {
		mf, mac := genForgedMsgMac(msg, msgHVs, sl)
		if isForged(mf, mac) {
			fmt.Printf("MD4-MAC successfully forged: %x\n", mac)
			fmt.Printf("Forged Message: %s\n", mf)
			fmt.Printf("Secret prefix length: %v\n", sl)
			break
		}
		sl += 1
	}

}

// Output:
// MD4-MAC successfully forged: 69384e45320924ab5e63fe5c17d834db
// Forged Message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon8;admin=true
// Secret prefix length: 90
