// Copyright © 2021 siddharth <s@ricketyspace.net>
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

	// Test 4
	m = ""
	sha1.Message(StrToBytes(m))
	h = sha1.Hash()
	e = "da39a3ee5e6b4b0d3255bfef95601890afd80709" // Expected hash.
	if BytesToHexStr(h) != e {
		t.Errorf("sha1 test 3 failed: %x != %s\n", h, e)
	}
}

// Test cases from RFC 2202
func TestHmacSha1(t *testing.T) {
	// Test 1
	k := FillBytes(0x0b, 20)
	m := StrToBytes("Hi There")
	h := HmacSha1(k, m)
	e := "b617318655057264e28bc0b6fb378c8ef146be00" // Expected HMAC-SHA1
	if BytesToHexStr(h) != e {
		t.Errorf("hmac-sha1 test 1 failed: %x != %s\n", h, e)
	}

	// Test 2
	k = StrToBytes("Jefe")
	m = StrToBytes("what do ya want for nothing?")
	h = HmacSha1(k, m)
	e = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" // Expected HMAC-SHA1
	if BytesToHexStr(h) != e {
		t.Errorf("hmac-sha1 test 2 failed: %x != %s\n", h, e)
	}

	// Test 3
	k = FillBytes(0xaa, 20)
	m = FillBytes(0xdd, 50)
	h = HmacSha1(k, m)
	e = "125d7342b9ac11cd91a39af48aa17b4f63f175d3" // Expected HMAC-SHA1
	if BytesToHexStr(h) != e {
		t.Errorf("hmac-sha1 test 3 failed: %x != %s\n", h, e)
	}

	// Test 4
	k = []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19,
	}
	m = FillBytes(0xcd, 50)
	h = HmacSha1(k, m)
	e = "4c9007f4026250c6bc8414f9bf50c86c2d7235da" // Expected HMAC-SHA1
	if BytesToHexStr(h) != e {
		t.Errorf("hmac-sha1 test 4 failed: %x != %s\n", h, e)
	}

	// Test 5
	k = FillBytes(0x0c, 20)
	m = StrToBytes("Test With Truncation")
	h = HmacSha1(k, m)
	e = "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04" // Expected HMAC-SHA1
	if BytesToHexStr(h) != e {
		t.Errorf("hmac-sha1 test 5 failed: %x != %s\n", h, e)
	}

	// Test 6
	k = FillBytes(0xaa, 80)
	m = StrToBytes("Test Using Larger Than Block-Size Key - Hash Key First")
	h = HmacSha1(k, m)
	e = "aa4ae5e15272d00e95705637ce8a3b55ed402112" // Expected HMAC-SHA1
	if BytesToHexStr(h) != e {
		t.Errorf("hmac-sha1 test 6 failed: %x != %s\n", h, e)
	}

	// Test 7
	k = FillBytes(0xaa, 80)
	m = StrToBytes("Test Using Larger Than Block-Size Key and")
	m = append(m, StrToBytes(" Larger Than One Block-Size Data")...)
	h = HmacSha1(k, m)
	e = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91" // Expected HMAC-SHA1
	if BytesToHexStr(h) != e {
		t.Errorf("hmac-sha1 test 7 failed: %x != %s\n", h, e)
	}

	// Test 8
	k = FillBytes(0xaa, 80)
	m = StrToBytes("Test Using Larger Than Block-Size Key - Hash Key First")
	h = HmacSha1(k, m)
	e = "aa4ae5e15272d00e95705637ce8a3b55ed402112" // Expected HMAC-SHA1
	if BytesToHexStr(h) != e {
		t.Errorf("hmac-sha1 test 8 failed: %x != %s\n", h, e)
	}

	// Test 9
	k = FillBytes(0xaa, 80)
	m = StrToBytes("Test Using Larger Than Block-Size Key and Larger")
	m = append(m, StrToBytes(" Than One Block-Size Data")...)
	h = HmacSha1(k, m)
	e = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91" // Expected HMAC-SHA1
	if BytesToHexStr(h) != e {
		t.Errorf("hmac-sha1 test 9 failed: %x != %s\n", h, e)
	}
}
