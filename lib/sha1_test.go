// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import "testing"

func TestSha1Hash(t *testing.T) {
	sha1 := Sha1{}
	sha1.Init([]uint32{})

	// Test 1
	m := "abc"
	sha1.Message(StrToBytes(m))
	h := sha1.Hash()
	e := "a9993e364706816aba3e25717850c26c9cd0d89d" // Expected hash.
	if BytesToHexStr(h) != e {
		t.Errorf("sha1 test 1 failed: %x != %s\n", h, e)
	}

	// Test 2
	m = "abcdbcdecdefdefgefghfghighijhi"
	m += "jkijkljklmklmnlmnomnopnopq"
	sha1.Message(StrToBytes(m))
	h = sha1.Hash()
	e = "84983e441c3bd26ebaae4aa1f95129e5e54670f1" // Expected hash.
	if BytesToHexStr(h) != e {
		t.Errorf("sha1 test 2 failed: %x != %s\n", h, e)
	}

	// Test 3
	m = ""
	m1 := "01234567012345670123456701234567"
	m1 += "01234567012345670123456701234567"
	for i := 0; i < 10; i++ {
		m += m1
	}
	sha1.Message(StrToBytes(m))
	h = sha1.Hash()
	e = "dea356a2cddd90c7a7ecedc5ebb563934f460452" // Expected hash.
	if BytesToHexStr(h) != e {
		t.Errorf("sha1 test 3 failed: %x != %s\n", h, e)
	}
}
