// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

func FillStr(a string, l int) string {
	b := ""
	if l < 1 {
		return b
	}
	for i := 0; i < l; i++ {
		b += a
	}
	return b
}
