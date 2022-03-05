// Copyright © 2022 siddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import "testing"

// Tests from
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
func TestSha256Hash(t *testing.T) {
	sha256 := Sha256{}
	sha256.Init([]uint32{})

	// Test 1
	m := "abc"
	sha256.Message(StrToBytes(m))
	h := sha256.Hash()
	e := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if BytesToHexStr(h) != e {
		t.Errorf("sha256 test 1 failed: %x != %s\n", h, e)
	}

	// Test 2
	m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
	sha256.Message(StrToBytes(m))
	h = sha256.Hash()
	e = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
	if BytesToHexStr(h) != e {
		t.Errorf("sha256 test 1 failed: %x != %s\n", h, e)
	}
}
