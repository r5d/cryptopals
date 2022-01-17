// Copyright © 2022 siddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import "testing"

func TestStrToNum(t *testing.T) {
	// Test 1
	s1 := "29283329"
	n1, err := StrToNum(s1)
	if err != nil {
		t.Errorf("test 1 failed: %v\n", err)
	}
	if n1 != 29283329 {
		t.Errorf("test 1 failed: %v != %v\n", s1, n1)
	}

	// Test 2
	s2 := "-83729282"
	n2, err := StrToNum(s2)
	if err != nil {
		t.Errorf("test 2 failed: %v\n", err)
	}
	if n2 != -83729282 {
		t.Errorf("test 2 failed: %v != %v\n", s2, n2)
	}

	// Test 3
	s3 := "887232.2323"
	_, err = StrToNum(s3)
	if err == nil {
		t.Errorf("test 3 failed\n")
	}

	// Test 4
	s4 := "332e323"
	_, err = StrToNum(s4)
	if err == nil {
		t.Errorf("test 4 failed\n")
	}
}
