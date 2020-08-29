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
	}
}