// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C28() {
	msg := lib.StrToBytes(`Nobody knows, why we keep tryin'
Why we keep tryin'

And so on it goes, I'm looking forward
To the next letter that I'm gonna get from you

A baby is born, as a man lay dying
As a man lay dying

And so on it goes, I'm looking forward
To the next letter that I'm gonna get from you

Sit beside me, watch the world burn
We'll never learn, we don't deserve nice things

And we'll scream, self-righteously
We did our best but what does that really mean

I'm walkin' around, walkin' around
With my head down, my head down

I'm pushin' away, I'm pushin' away
Yeah I'm pushin' away, pushin' away`)
	sec := lib.StrToBytes("Milk Records")

	// Generate SHA1 MAC.
	mac := lib.Sha1Mac(sec, msg)

	// Verify.
	if lib.Sha1MacVerify(sec, msg, mac) != true {
		fmt.Printf("Error: Sha1Mac verification failed!\n")
		return
	}

	// Modify msg
	msg[42] = byte(42)

	// Verify that SHA1 MAC fails
	if lib.Sha1MacVerify(sec, msg, mac) != false {
		fmt.Printf("Error: Sha1Mac verification success!\n")
		return
	}
	fmt.Printf("OK\n")
}

// Output:
// OK
