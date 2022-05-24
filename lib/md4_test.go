// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import "testing"

func TestMd4Hash(t *testing.T) {
	md4 := Md4{}
	md4.Init([]uint32{})

	// Test 1
	m := "abc"
	md4.Message(StrToBytes(m))
	h := md4.Hash()
	e := "a448017aaf21d8525fc10ae87aa6729d" // Expected hash.
	if BytesToHexStr(h) != e {
		t.Errorf("md4 test 1 failed: %x != %s\n", h, e)
	}

	// Test 2
	m = "message digest"
	md4.Message(StrToBytes(m))
	h = md4.Hash()
	e = "d9130a8164549fe818874806e1c7014b" // Expected hash.
	if BytesToHexStr(h) != e {
		t.Errorf("md4 test 2 failed: %x != %s\n", h, e)
	}

	// Test 3
	m = "abcdefghijklmnopqrstuvwxyz"
	md4.Message(StrToBytes(m))
	h = md4.Hash()
	e = "d79e1c308aa5bbcdeea8ed63df412da9" // Expected hash.
	if BytesToHexStr(h) != e {
		t.Errorf("md4 test 3 failed: %x != %s\n", h, e)
	}

	// Test 4
	m = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	md4.Message(StrToBytes(m))
	h = md4.Hash()
	e = "043f8582f241db351ce627e153e7f0e4" // Expected hash.
	if BytesToHexStr(h) != e {
		t.Errorf("md4 test 4 failed: %x != %s\n", h, e)
	}

	// Test 5
	m = "123456789012345678901234567890123456789012345678901234567890123456"
	m += "78901234567890"
	md4.Message(StrToBytes(m))
	h = md4.Hash()
	e = "e33b4ddc9c38f2199c3e7b164fcc0536" // Expected hash.
	if BytesToHexStr(h) != e {
		t.Errorf("md4 test 5 failed: %x != %s\n", h, e)
	}

}

func TestMd4MacVerify(t *testing.T) {
	md4 := Md4{}
	md4.Init([]uint32{})

	sec := StrToBytes("honey")
	msg := StrToBytes("abc")

	// Test Mac
	mac := md4.Mac(sec, msg)
	e := "22fd3b98ca4a901fec432ed2c49d3f83" // Expected Mac
	if BytesToHexStr(mac) != e {
		t.Errorf("Error: md5 mac failed %x != %s\n", mac, e)
	}

	// Test MacVerify.
	if !md4.MacVerify(sec, msg, mac) {
		t.Errorf("Error: mac verification failed\n")
	}
}
