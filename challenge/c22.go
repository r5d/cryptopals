// Copyright © 2021 siddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"
	"time"

	"ricketyspace.net/cryptopals/lib"
)

func C22() {
	mt := new(lib.MTRand)
	minWait := 40 * time.Second
	maxWait := 1000 * time.Second
	randomWait := func() {
		fmt.Printf("Waiting for a random amount of time...\n")
		s := time.Now()
		lib.SleepRandom(minWait, maxWait)
		fmt.Printf("Elapsed time %v\n", time.Now().Sub(s))
	}

	fmt.Printf("This challenge might take ~%v to ~%v to complete\n",
		2*minWait, 2*maxWait)

	randomWait()
	fmt.Printf("Generating seed from current time...\n")
	mt.Seed(uint32(time.Now().Unix()))
	randomWait()

	fmt.Printf("Extracting first random 32-bit garbage fron RNG...\n")
	random := mt.Extract()

	fmt.Printf("Cracking seed...\n")
	guess := uint32(time.Now().Unix())
	for {
		mt.Seed(guess)
		x := mt.Extract()
		if x == random {
			fmt.Printf("Found seed %v\n", guess)
			break
		}
		guess = guess - 1
	}
}

// Output:
// This challenge might take ~1m20s to ~33m20s to complete
// Waiting for a random amount of time...
// Elapsed time 10m51.671176141s
// Generating seed from current time...
// Waiting for a random amount of time...
// Elapsed time 14m48.257182374s
// Extracting first random 32-bit garbage fron RNG...
// Cracking seed...
// Found seed 1625112975
