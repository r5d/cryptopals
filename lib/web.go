// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import "crypto/rand"

type Profile map[string]string

var webSessionEncryptionKey []byte = make([]byte, 16)
var webUidCounter int64
var webUserProfiles map[string]Profile = make(map[string]Profile, 0)

func init() {
	_, err := rand.Read(webSessionEncryptionKey)
	if err != nil {
		panic(err)
	}
	webUidCounter = 10000
}

func WebGenUid() int64 {
	uid := webUidCounter
	webUidCounter += 1

	return uid
}

func WebParseKeyValue(encoded string) map[string]string {
	m := make(map[string]string, 0)

	kvs := StrSplitAt('&', encoded)
	for i := 0; i < len(kvs); i++ {
		kv := StrSplitAt('=', kvs[i])
		m[StripSpaceChars(kv[0])] = kv[1]
	}
	return m
}

func WebProfileFor(email string) string {
	e := WebSanitizeEmail(email)
	if len(e) == 0 {
		panic("email invalid")
	}

	if p, ok := webUserProfiles[e]; ok {
		// Profile already exists.
		return WebEncodeProfile(p)
	}

	// Create profile.
	p := make(Profile, 0)
	p["email"] = e
	p["uid"] = NumToStr(WebGenUid())
	p["role"] = "user"
	webUserProfiles[e] = p

	return WebEncodeProfile(p)
}

func WebEncodeProfile(p Profile) string {
	ep := "email=" + p["email"] // Encoded profile.
	ep += "&uid=" + p["uid"]
	ep += "&role=" + p["role"]
	return ep
}

func WebDecodeProfile(encoded string) Profile {
	return WebParseKeyValue(encoded)
}

func WebEncryptProfile(encoded string) []byte {
	return AESEncryptECB(StrToBytes(encoded), webSessionEncryptionKey)
}

func WebDecryptProfile(cipher []byte) string {
	return BytesToStr(AESDecryptECB(cipher, webSessionEncryptionKey))
}

func WebSanitizeEmail(email string) string {
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
