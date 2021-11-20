// Copyright © 2021 siddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import "time"

// Sleeps for atleast `min` but not more than `max`.
func SleepRandom(min, max time.Duration) {
	time.Sleep(time.Duration(RandomInt(int64(min), int64(max))))
}

// Sleep for `d` nano seconds.
func Sleep(d time.Duration) {
	time.Sleep(d)
}
