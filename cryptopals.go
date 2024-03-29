// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package main

import (
	"flag"

	"ricketyspace.net/cryptopals/challenge"
)

var c = flag.Int("c", 0, "Challenge to run")
var s = flag.Bool("s", false, "Start HTTP server for a challenge")

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
	case 24:
		challenge.C24()
	case 25:
		challenge.C25()
	case 26:
		challenge.C26()
	case 27:
		challenge.C27()
	case 28:
		challenge.C28()
	case 29:
		challenge.C29()
	case 30:
		challenge.C30()
	case 31:
		challenge.C31(*s)
	case 32:
		challenge.C32(*s)
	case 33:
		challenge.C33()
	case 34:
		challenge.C34(flag.Args())
	case 35:
		challenge.C35(flag.Args())
	case 36:
		challenge.C36(flag.Args())
	case 37:
		challenge.C37(flag.Args())
	case 38:
		challenge.C38(flag.Args())
	case 39:
		challenge.C39()
	case 40:
		challenge.C40()
	case 41:
		challenge.C41()
	}
}
