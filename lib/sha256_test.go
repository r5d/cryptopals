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

// Tests from
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip
// L=32
func TestHmacSha256(t *testing.T) {
	// Test 1
	k := HexStrToBytes("6f35628d65813435534b5d67fbdb54cb33403d04e843103e6399f806cb5df95febbdd61236f33245")
	m := HexStrToBytes("752cff52e4b90768558e5369e75d97c69643509a5e5904e0a386cbe4d0970ef73f918f675945a9aefe26daea27587e8dc909dd56fd0468805f834039b345f855cfe19c44b55af241fff3ffcd8045cd5c288e6c4e284c3720570b58e4d47b8feeedc52fd1401f698a209fccfa3b4c0d9a797b046a2759f82a54c41ccd7b5f592b")
	h := HmacSha256(k, m)
	e := "05d1243e6465ed9620c9aec1c351a1868e2251b933a394752ab17bff99b80e29" // Expected HMAC-SHA256
	if BytesToHexStr(h) != e {
		t.Errorf("hmac-sha256 test 1 failed: %x != %s\n", h, e)
	}

	// Test 2
	k = HexStrToBytes("42521bc3f168b2b3434cb4e44d92f526b41c5f10bfe0a0e6b0eb20c055a636e9da599b86e1ed1f78d4f69a837af126afc9c98beefca1fb00e5cd00948321b2b0")
	m = HexStrToBytes("5a600c468ec22e42af5ba93eb79452864ebe469a86f83632c85201800f3288b553f7bec649ddfe704920a27a8f65d13aa755985a238b3cdc8fb0cf5ca7e40295c7603a27a25ae69837290f9801aa30896ee2493e93e52f031ef626de8cefb1159ce4a9f003038dc061be1920742d1a7b8bad80cf3eceb5b05d6c2d8f261b3f3c")
	h = HmacSha256(k, m)
	e = "e1c3c6d90820511c8d685c73bb757ee216ce143989cd540ae27c8eb09bff33ed" // Expected HMAC-SHA256
	if BytesToHexStr(h) != e {
		t.Errorf("hmac-sha256 test 2 failed: %x != %s\n", h, e)
	}

	// Test 3
	k = HexStrToBytes("1abf71698a7d52b41caa5c26558d46e8cf27a490d270168c23e4c0c4213efa7b0d844876aa438c61061c7a6e977f4d3f89b7b806572720eb99d308ae1d22cd8d38e293685e8c")
	m = HexStrToBytes("aa02f0b377f161ee60b0fbd6c56a537c0358cb8da62b63d5daaad203239cd6ac4ee8c892a8fb73256d6a264a83d8085c681bac706a9ae5de16f9dcfdf2f95f2d6f997c1b19824f4011a118abbd169001be4d7ec2226a85cddbeb4027708891f8f35e35d6334d9c46329ff880daea9573eb3768093863eaac13c6270906131114")
	h = HmacSha256(k, m)
	e = "8cbd8f921c55d36e5b7db27f7891def17ed6ff32d155b2660b7fe26870a0b243" // Expected HMAC-SHA256
	if BytesToHexStr(h) != e {
		t.Errorf("hmac-sha256 test 3 failed: %x != %s\n", h, e)
	}
}
