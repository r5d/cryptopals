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
	}
}
