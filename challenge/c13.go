// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C13() {
	type Profile map[string]string

	key, err := lib.RandomBytes(16)
	if err != nil {
		fmt.Printf("key generation error: %v\n", err)
	}
	counter := int64(10000)
	profiles := make(map[string]Profile, 0)

	genUid := func() int64 {
		uid := counter
		counter += 1

		return uid
	}
	parse := func(encoded string) map[string]string {
		m := make(map[string]string, 0)

		kvs := lib.StrSplitAt('&', encoded)
		for i := 0; i < len(kvs); i++ {
			kv := lib.StrSplitAt('=', kvs[i])
			m[lib.StripSpaceChars(kv[0])] = kv[1]
		}
		return m
	}
	encode := func(p Profile) string {
		ep := "email=" + p["email"] // Encoded profile.
		ep += "&uid=" + p["uid"]
		ep += "&role=" + p["role"]
		return ep
	}
	decode := func(encoded string) Profile {
		return parse(encoded)
	}
	encrypt := func(encoded string) []byte {
		return lib.AESEncryptECB(lib.StrToBytes(encoded), key)
	}
	decrypt := func(cipher []byte) string {
		return lib.BytesToStr(lib.AESDecryptECB(cipher, key))
	}
	sanitize := func(email string) string {
		if len(email) < 1 {
			return ""
		}
		se := "" // sanitized email

		// Strip meta characters
		for i := 0; i < len(email); i++ {
			if email[i] == '&' || email[i] == '=' {
				continue
			}
			se += string(email[i])
		}
		return se
	}
	profileFor := func(email string) string {
		e := sanitize(email)
		if len(e) == 0 {
			panic("email invalid")
		}

		if p, ok := profiles[e]; ok {
			// Profile already exists.
			return encode(p)
		}

		// Create profile.
		p := make(Profile, 0)
		p["email"] = e
		p["uid"] = lib.NumToStr(genUid())
		p["role"] = "user"
		profiles[e] = p

		return encode(p)
	}
	adminBlock := lib.BytesToStr(lib.Pkcs7Padding(lib.StrToBytes("admin"), 16))
	ep := profileFor("foo@abacus" + adminBlock)
	encryptedEP := encrypt(ep)
	adminBlockCipher := encryptedEP[16:32] // Second block in the cipher

	ep = profileFor("foo@abacus")
	encryptedEP = encrypt(ep)
	for i := 0; i < 16; i++ { // Replace last block with the admin cipher block.
		encryptedEP[32+i] = adminBlockCipher[i]
	}
	adminEP := decrypt(encryptedEP)
	adminProfile := decode(adminEP)
	fmt.Printf("Admin Encoded Profile: %v\n", adminEP)
	fmt.Printf("Admin Profile: %v\n", adminProfile)
}

// Output:
// Admin Encoded Profile: email=foo@abacus&uid=10001&role=admin
// Admin Profile: map[email:foo@abacus role:admin uid:10001]
