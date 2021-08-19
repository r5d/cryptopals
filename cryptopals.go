// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package main

import (
	"flag"

	"ricketyspace.net/cryptopals/challenge"
)

var c = flag.Int("c", 0, "Challenge to run")

func init() {
	flag.Parse()
}

func main() {
	switch *c {
	case 0:
		flag.PrintDefaults()
	case 1:
		challenge.C1()
	case 2:
		challenge.C2()
	case 3:
		challenge.C3()
	case 4:
		challenge.C4()
	case 5:
		challenge.C5()
	case 6:
		challenge.C6()
	case 7:
		challenge.C7()
	case 8:
		challenge.C8()
	case 9:
		challenge.C9()
	case 10:
		challenge.C10()
	case 11:
		challenge.C11()
	case 12:
		challenge.C12()
	case 13:
		challenge.C13()
	case 14:
		challenge.C14()
	case 15:
		challenge.C15()
	case 16:
		challenge.C16()
	case 17:
		challenge.C17()
	case 18:
		challenge.C18()
	case 19:
		challenge.C19()
	case 20:
		challenge.C20()
	case 21:
		challenge.C21()
	case 22:
		challenge.C22()
	case 23:
		challenge.C23()
	}
}
