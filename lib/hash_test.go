// Copyright © 2022 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import (
	"testing"
)

func TestShaShr(t *testing.T) {
	s := uint32(256)
	sr := shaShr(s, 2)
	if sr != s>>2 {
		t.Errorf("shaShr test failed")
	}
}
